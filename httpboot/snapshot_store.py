"""Private content-addressed saves with session-fenced atomic snapshot commits."""
import base64
import hashlib
import json
import re
import secrets
from pathlib import Path, PurePosixPath
from common import atomic

CHUNK_SIZE = 1024 * 1024
DIGEST = re.compile(r'^[0-9a-f]{64}$')
MAX_FILES = 100000


def needs_clean(rule):
    folder=rule['folder'].lower()
    roots=('.config/google-chrome','.config/chatgpt','.config/codex','.codex')
    return rule['mode'] in ('app-and-data','closed-folder') or folder.startswith('.var/app/') or any(folder==root or folder.startswith(root+'/') for root in roots)


def coherent_folders(rules):
    folders={r['folder'] for r in rules if needs_clean(r)}
    if folders and any(r['folder']=='.local/share/keyrings' for r in rules):folders.add('.local/share/keyrings')
    return folders


def relative(value):
    if not isinstance(value, str) or not value or len(value) > 1024 or '\x00' in value:
        raise ValueError('Invalid snapshot path')
    path = PurePosixPath(value)
    if path.is_absolute() or any(p in ('', '.', '..') for p in value.split('/')):
        raise ValueError('Snapshot path must remain inside its selected folder')
    return value


def manifest(value):
    if not isinstance(value, dict) or len(value) > MAX_FILES:
        raise ValueError('Snapshot manifest is too large')
    total = 0
    for name, record in value.items():
        relative(name)
        if isinstance(record,dict) and set(record)=={'link'}:
            target=record['link']
            if not isinstance(target,str) or not target or len(target)>1024 or '\x00' in target or target.startswith('/'):
                raise ValueError('Snapshot link must remain inside its selected folder')
            continue
        if not isinstance(record, dict) or not {'size','chunks'}<=set(record) or set(record)-{'size','chunks','mode'}:
            raise ValueError('Invalid snapshot file')
        if 'mode' in record and (type(record['mode']) is not int or record['mode']&~0o700):raise ValueError('Privileged or shared file modes are not permitted')
        if type(record['size']) is not int or not 0 <= record['size'] <= 64*1024**3:
            raise ValueError('Invalid file size')
        chunks = record['chunks']
        if not isinstance(chunks, list) or len(chunks) != (record['size']+CHUNK_SIZE-1)//CHUNK_SIZE:
            raise ValueError('Invalid chunk count')
        if any(not isinstance(d, str) or not DIGEST.fullmatch(d) for d in chunks):
            raise ValueError('Invalid chunk checksum')
        total += record['size']
        if total > 256*1024**3:
            raise ValueError('Snapshot exceeds size limit')
    # A file cannot also be a parent directory.
    for name in value:
        if any(str(parent) in value for parent in PurePosixPath(name).parents if str(parent) != '.'):
            raise ValueError('Conflicting snapshot paths')
    # Resolve the virtual link graph, never the Server filesystem. Even chains
    # involving '..' must stay inside this one selected folder.
    for name,record in value.items():
        if 'link' not in record:continue
        current=name.split('/')[:-1];pending=record['link'].split('/');hops=0
        while pending:
            part=pending.pop(0)
            if part in ('','.'):continue
            if part=='..':
                if not current:raise ValueError('Snapshot link escapes its selected folder')
                current.pop();continue
            current.append(part);other=value.get('/'.join(current),{})
            if 'link' in other:
                hops+=1
                if hops>40:raise ValueError('Snapshot link cycle or excessive chain')
                current.pop();pending=other['link'].split('/')+pending
    return value


class Snapshots:
    def __init__(self, authority):
        self.authority = authority
        self.root = authority.database.parent/'saves'
        self.root.mkdir(mode=0o700, exist_ok=True)
        with authority.db() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS objects (owner TEXT, digest TEXT, size INTEGER,
                PRIMARY KEY(owner,digest));
            CREATE TABLE IF NOT EXISTS snapshot_stages (id TEXT PRIMARY KEY, owner TEXT, token TEXT, folder TEXT, files TEXT);
            CREATE TABLE IF NOT EXISTS snapshots (id TEXT PRIMARY KEY, owner TEXT,
                rule TEXT, manifest TEXT, created REAL, consistency TEXT);
            ''')
            db.execute('CREATE TABLE IF NOT EXISTS snapshot_checkpoints (id TEXT PRIMARY KEY, owner TEXT, mapping TEXT, created REAL)')
            if 'stamp' not in {row[1] for row in db.execute('PRAGMA table_info(objects)')}:
                db.execute('ALTER TABLE objects ADD COLUMN stamp TEXT')

    def object_path(self, owner, digest):
        if not DIGEST.fullmatch(digest):
            raise ValueError('Invalid object checksum')
        # Owner is an account validated in the authority; never accept a path.
        namespace = hashlib.sha256(owner.encode()).hexdigest()
        folder = self.root/namespace/digest[:2]
        folder.mkdir(parents=True, mode=0o700, exist_ok=True)
        return folder/digest

    def authorize(self, db, peer, data):
        self.authority.session(db, peer, data['name'], data['token'])
        return data['name']

    def rule(self, db, owner, folder):
        row = db.execute('SELECT * FROM accounts WHERE name=?', (owner,)).fetchone()
        return next((r for r in self.authority.effective_rules(db,row) if r['folder'] == folder), None)

    def dispatch(self, route, peer, data):
        if not isinstance(data, dict):
            raise ValueError('Snapshot request required')
        with self.authority.db(write=route not in ('get','latest','history','manifest-page','restore-set')) as db:
            owner = self.authorize(db, peer, data)
            if route in ('checkpoint','restore-set'):
                account=db.execute('SELECT * FROM accounts WHERE name=?',(owner,)).fetchone()
                rules=self.authority.effective_rules(db,account);required=coherent_folders(rules)
                if route=='restore-set':
                    row=db.execute('SELECT id,mapping FROM snapshot_checkpoints WHERE owner=? ORDER BY rowid DESC LIMIT 1',(owner,)).fetchone()
                    return {'checkpoint':row['id'] if row else None,'snapshots':{k:v for k,v in json.loads(row['mapping']).items() if k in required} if row else {}}
                mapping=data.get('snapshots')
                if data.get('apps_closed') is not True or not isinstance(mapping,dict) or set(mapping)!=required:
                    raise ValueError('A complete closed-application save is required before preserving sign-in state')
                for folder,identifier in mapping.items():
                    if not isinstance(identifier,str) or not db.execute('SELECT 1 FROM snapshots WHERE id=? AND owner=? AND rule=?',(identifier,owner,folder)).fetchone():
                        raise ValueError('Checkpoint snapshot is not authorized for this account and folder')
                encoded=json.dumps(mapping,sort_keys=True)
                prior=db.execute('SELECT id,mapping FROM snapshot_checkpoints WHERE owner=? ORDER BY rowid DESC LIMIT 1',(owner,)).fetchone()
                if prior and prior['mapping']==encoded:return {'ok':True,'id':prior['id']}
                identifier=secrets.token_hex(16)
                db.execute('INSERT INTO snapshot_checkpoints VALUES (?,?,?,?)',(identifier,owner,encoded,self.authority.clock()))
                stale=list(db.execute('SELECT id FROM snapshot_checkpoints WHERE owner=? ORDER BY rowid DESC LIMIT -1 OFFSET 3',(owner,)))
                for row in stale:db.execute('DELETE FROM snapshot_checkpoints WHERE id=?',(row[0],))
                return {'ok':True,'id':identifier}
            if route == 'missing':
                hashes = data['hashes']
                if not isinstance(hashes, list) or len(hashes) > 4096 or any(not isinstance(d,str) or not DIGEST.fullmatch(d) for d in hashes):
                    raise ValueError('Invalid object list')
                missing=[]
                for digest in hashes:
                    row=db.execute('SELECT size,stamp FROM objects WHERE owner=? AND digest=?',(owner,digest)).fetchone()
                    path=self.object_path(owner,digest)
                    if not row or not path.is_file():missing.append(digest);continue
                    st=path.stat();stamp=json.dumps([st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns])
                    if row['stamp']!=stamp:
                        if st.st_size!=row['size'] or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
                            db.execute('DELETE FROM objects WHERE owner=? AND digest=?',(owner,digest));missing.append(digest)
                        else:db.execute('UPDATE objects SET stamp=? WHERE owner=? AND digest=?',(stamp,owner,digest))
                return {'missing':missing}
            if route == 'put':
                digest = data['digest']
                if not isinstance(data['content'],str) or len(data['content']) > 4*((CHUNK_SIZE+2)//3):
                    raise ValueError('Object is too large')
                content = base64.b64decode(data['content'],validate=True)
                if len(content) > CHUNK_SIZE or hashlib.sha256(content).hexdigest() != digest:
                    raise ValueError('Object checksum mismatch')
                target = self.object_path(owner,digest)
                atomic(target,content)
                st=target.stat();stamp=json.dumps([st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns])
                db.execute('INSERT OR REPLACE INTO objects(owner,digest,size,stamp) VALUES (?,?,?,?)',(owner,digest,len(content),stamp))
                return {'ok':True}
            if route == 'get':
                digest=data['digest']
                if not db.execute('SELECT 1 FROM objects WHERE owner=? AND digest=?',(owner,digest)).fetchone():
                    raise ValueError('Object is not authorized for this account')
                content=self.object_path(owner,digest).read_bytes()
                if hashlib.sha256(content).hexdigest()!=digest:
                    raise ValueError('Stored object failed verification')
                return {'content':base64.b64encode(content).decode()}
            stage_id=data.get('stage')
            if stage_id:
                staged=db.execute('SELECT * FROM snapshot_stages WHERE id=? AND owner=? AND token=?',(stage_id,owner,data['token'])).fetchone()
                if not staged:raise ValueError('Unknown or stale snapshot staging transaction')
                data={**data,'folder':staged['folder'],'files':json.loads(staged['files']) if route=='commit' else data.get('files')}
            folder=data['folder']
            rule=self.rule(db,owner,folder)
            if rule is None:
                raise ValueError('Folder is not selected by Server policy')
            if route=='begin':
                stage=secrets.token_hex(16)
                db.execute('INSERT INTO snapshot_stages VALUES (?,?,?,?,?)',(stage,owner,data['token'],folder,'{}'))
                return {'stage':stage}
            if route=='stage':
                if not stage_id:raise ValueError('Snapshot staging transaction required')
                incoming=manifest(data['files']);combined=json.loads(staged['files'])
                combined.update(incoming);manifest(combined)
                db.execute('UPDATE snapshot_stages SET files=? WHERE id=?',(json.dumps(combined),stage_id))
                return {'ok':True}
            if route=='manifest-page':
                snapshot=db.execute('SELECT manifest FROM snapshots WHERE id=? AND owner=? AND rule=?',(data['id'],owner,folder)).fetchone()
                if not snapshot:raise ValueError('Snapshot is not authorized')
                files=json.loads(snapshot[0]);offset=data.get('offset',0)
                if type(offset) is not int or not 0<=offset<=len(files):raise ValueError('Invalid manifest offset')
                keys=sorted(files);page={};count=0
                for key in keys[offset:]:
                    encoded=json.dumps({key:files[key]})
                    if page and count+len(encoded)>2*1024**2:break
                    page[key]=files[key];count+=len(encoded)
                following=offset+len(page)
                return {'files':page,'next':following if following<len(files) else None}
            if route == 'latest':
                if data.get('snapshot') is not None:
                    if not isinstance(data['snapshot'],str):raise ValueError('Invalid verified app snapshot reference')
                    row=db.execute('SELECT * FROM snapshots WHERE owner=? AND rule=? AND id=?',(owner,folder,data['snapshot'])).fetchone()
                    if row is None:raise ValueError('Verified app save-set snapshot is unavailable; previous data retained')
                else:row=db.execute('SELECT * FROM snapshots WHERE owner=? AND rule=? ORDER BY rowid DESC LIMIT 1',(owner,folder)).fetchone()
                result=dict(row) if row else None
                if result:result.pop('manifest')
                return {'snapshot':result}
            if route == 'history':
                return {'snapshots':[dict(r) for r in db.execute('SELECT id,created,consistency FROM snapshots '
                    'WHERE owner=? AND rule=? ORDER BY rowid DESC LIMIT 100',(owner,folder))]}
            if route != 'commit':
                raise ValueError('Unknown snapshot operation')
            files=manifest(data['files'])
            if rule['mode']=='app-only':
                allowed=db.execute("SELECT value FROM settings WHERE key='sources'").fetchone()
                if rule['source'] not in (json.loads(allowed[0]) if allowed else []):raise ValueError('Application installation source is no longer approved')
            clean_required=needs_clean(rule)
            if clean_required and data.get('app_closed') is not True:
                raise ValueError('Application must close before its databases can be saved')
            encoded=json.dumps(files,sort_keys=True,separators=(',',':'))
            previous=db.execute('SELECT id,manifest FROM snapshots WHERE owner=? AND rule=? ORDER BY rowid DESC LIMIT 1',(owner,folder)).fetchone()
            if previous and previous['manifest']==encoded:
                if stage_id:db.execute('DELETE FROM snapshot_stages WHERE id=?',(stage_id,))
                return {'ok':True,'id':previous['id'],'unchanged':True}
            # Verify immutable content without holding the authority write lock.
            # Recheck the session and policy in the final publication transaction.
            db.commit()
            verified=set()
            for record in files.values():
                if 'link' in record:continue
                remaining=record['size']
                for digest in record['chunks']:
                    size=min(CHUNK_SIZE,remaining)
                    if (digest,size) in verified:remaining-=size;continue
                    row=db.execute('SELECT size,stamp FROM objects WHERE owner=? AND digest=?',(owner,digest)).fetchone()
                    path=self.object_path(owner,digest)
                    if not row or row['size']!=size or not path.is_file():
                        raise ValueError('Snapshot content is missing or has the wrong size')
                    st=path.stat();stamp=json.dumps([st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns])
                    if row['stamp']!=stamp:
                        stored=path.read_bytes()
                        if len(stored)!=size or hashlib.sha256(stored).hexdigest()!=digest:
                            raise ValueError('Stored content failed commit verification')
                    verified.add((digest,size))
                    remaining-=size
            db.execute('BEGIN IMMEDIATE')
            self.authority.session(db,peer,owner,data['token'])
            if self.rule(db,owner,folder)!=rule:raise ValueError('Persistence policy changed during verification; retry')
            identifier=secrets.token_hex(16)
            db.execute('INSERT INTO snapshots VALUES (?,?,?,?,?,?)',
                       (identifier,owner,folder,encoded,self.authority.clock(),'verified-installation' if rule['mode']=='app-only' else 'closed-app' if clean_required else 'verified-transfer'))
            retention=db.execute("SELECT value FROM settings WHERE key='snapshot-retention'").fetchone()
            keep=int(retention[0]) if retention else 5
            stale=[row[0] for row in db.execute('SELECT id FROM snapshots WHERE owner=? AND rule=? ORDER BY rowid DESC LIMIT -1 OFFSET ?',(owner,folder,keep))]
            protected=set()
            for row in db.execute('SELECT mapping FROM snapshot_checkpoints WHERE owner=?',(owner,)):protected.update(json.loads(row[0]).values())
            for old in stale:
                if old not in protected:db.execute('DELETE FROM snapshots WHERE id=?',(old,))
            # Transaction commit publishes the entire manifest. Existing snapshots survive failure.
            if stage_id:db.execute('DELETE FROM snapshot_stages WHERE id=?',(stage_id,))
            return {'ok':True,'id':identifier,'unchanged':False}
