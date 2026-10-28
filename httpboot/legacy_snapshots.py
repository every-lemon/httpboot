"""Import completed legacy snapshots without changing or deleting their source."""
import hashlib
import json
import re
import secrets
from pathlib import Path
from common import atomic,load,validate_config
from persistence_v2 import Home
from snapshot_store import CHUNK_SIZE,manifest

LABELS={
 'chrome':{'profile':'.config/google-chrome','keyrings':'.local/share/keyrings'},
 'workspace':{'workspace':'workspace'},
 'games':{'prism':'.var/app/org.prismlauncher.PrismLauncher','sober':'.var/app/org.vinegarhq.Sober','keyrings':'.local/share/keyrings'},
 'chatgpt':{'profile':'.config/ChatGPT','lowercase':'.config/chatgpt','codex_app':'.config/Codex','codex':'.codex','keyrings':'.local/share/keyrings'},
 'desktop':{'appearance':'.local/share/httpboot/desktop-state'}}


def import_latest(authority,config_path):
    config=validate_config(load(config_path));count=0
    for user in config['users']:
        name=user['name']
        with authority.db() as db:
            if db.execute('SELECT 1 FROM sessions WHERE name=?',(name,)).fetchone():raise ValueError('Release active v2 sessions before importing legacy saves')
            if not db.execute('SELECT 1 FROM accounts WHERE name=? AND uid=?',(name,user['uid'])).fetchone():raise ValueError('Import stable accounts before importing saves')
        for kind,labels in LABELS.items():
            base=Path(config['data_dir'])/'users'/name/kind
            if not base.is_dir() or base.is_symlink():continue
            candidates=sorted((p.name for p in base.iterdir() if re.fullmatch(r'\d{20}-[0-9a-f]{8}',p.name)),reverse=True)
            for token in candidates:
                home=Home(base,owner=user['uid'])
                try:
                    with home.file(token,'.complete') as marker:expected=marker.read(128).decode()
                    with home.file(token,'manifest.json') as stream:raw=stream.read(32*1024*1024)
                    if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('Legacy manifest checksum mismatch')
                    metadata=json.loads(raw)
                    if metadata.get('schema')!=1 or metadata.get('user')!=name or metadata.get('kind')!=kind:raise ValueError('Legacy snapshot identity mismatch')
                    actual=dict(home.walk(token,allow_links=True));actual.pop('manifest.json',None);actual.pop('.complete',None)
                    if set(actual)!=set(metadata['files']):raise ValueError('Legacy snapshot inventory changed')
                    prepared={label:{} for label in labels};objects={}
                    for path,info in actual.items():
                        details=metadata['files'][path];parts=path.split('/',1)
                        if len(parts)!=2 or parts[0] not in labels:raise ValueError('Legacy snapshot contains unknown content')
                        if 'link' in details:
                            if info!=details:raise ValueError('Legacy link changed during migration')
                            prepared[parts[0]][parts[1]]={'link':details['link']};continue
                        chunks=[];digest=hashlib.sha256();size=0
                        with home.file(token,path) as stream:
                            while True:
                                block=stream.read(CHUNK_SIZE)
                                if not block:break
                                key=hashlib.sha256(block).hexdigest();digest.update(block);size+=len(block);chunks.append(key)
                                target=authority.snapshots.object_path(name,key)
                                if not target.exists():atomic(target,block)
                                objects[key]=len(block)
                        if size!=details['size'] or digest.hexdigest()!=details['sha256']:raise ValueError('Legacy file failed verification')
                        prepared[parts[0]][parts[1]]={'size':size,'chunks':chunks,'mode':info[5]}
                    with authority.db() as db:
                        if db.execute('SELECT 1 FROM sessions WHERE name=?',(name,)).fetchone():raise ValueError('Account became active during migration; staged objects retained')
                        for key,size in objects.items():db.execute('INSERT OR IGNORE INTO objects(owner,digest,size) VALUES (?,?,?)',(name,key,size))
                        for label,files in prepared.items():
                            manifest(files);folder=labels[label]
                            # Keyring copies from several app categories select the newest save.
                            current=db.execute('SELECT created FROM snapshots WHERE owner=? AND rule=? ORDER BY rowid DESC LIMIT 1',(name,folder)).fetchone()
                            saved=metadata.get('saved_at',int(token.split('-')[0])/1e9)
                            if current and current[0]>=saved:continue
                            db.execute('INSERT INTO snapshots VALUES (?,?,?,?,?,?)',(secrets.token_hex(16),name,folder,json.dumps(files,sort_keys=True,separators=(',',':')),saved,'legacy-verified-transfer'))
                            row=db.execute('SELECT rules FROM accounts WHERE name=?',(name,)).fetchone();rules=json.loads(row[0])
                            if not any(rule['folder']==folder for rule in rules):
                                rules.append({'folder':folder,'mode':'folder','source':None})
                                db.execute('UPDATE accounts SET rules=? WHERE name=?',(json.dumps(rules),name))
                            count+=1
                    break
                except FileNotFoundError:continue # Incomplete snapshots remain on the old service.
    return {'ok':True,'folders_imported':count,'legacy_sources_preserved':True}
