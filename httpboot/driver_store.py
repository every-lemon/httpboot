"""Authenticated device submissions; only Server administrators approve imports."""
import base64
import fcntl
import hashlib
import json
import os
import re
import secrets
import time
from pathlib import Path
from common import atomic,dump,load,sha256
from driver_imports import inspect,approve

LIMIT=512*1024**2
CHUNK=1024**2


class Imports:
    def __init__(self,authority):
        self.authority=authority;self.root=authority.database.parent/'driver-submissions'
        self.root.mkdir(mode=0o700,exist_ok=True)
    def directory(self,identifier):
        if not re.fullmatch('[a-f0-9]{32}',identifier):raise ValueError('Invalid driver submission')
        return self.root/identifier
    def dispatch(self,peer,action,data):
        with self.authority.db() as db:self.authority.device(db,peer)
        with open(self.root/'uploads.lock','a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            if action=='begin':
                required={'filename','size','sha256','kernel','hardware_ids','provenance'}
                if not isinstance(data,dict) or set(data)!=required:raise ValueError('Invalid driver submission metadata')
                if type(data['size']) is not int or not 0<data['size']<=LIMIT:raise ValueError('Driver import exceeds 512 MiB')
                if not re.fullmatch('[a-f0-9]{64}',data['sha256']):raise ValueError('Invalid driver digest')
                if not re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}\.(deb|bin|fw|ucode)',data['filename']):raise ValueError('Invalid driver filename')
                if not isinstance(data['hardware_ids'],list) or not 0<len(data['hardware_ids'])<=128 or any(not isinstance(v,str) or len(v)>256 for v in data['hardware_ids']):raise ValueError('Invalid hardware IDs')
                if not isinstance(data['provenance'],str) or not 0<len(data['provenance'])<=1024:raise ValueError('Invalid provenance')
                if not isinstance(data['kernel'],str) or not re.fullmatch(r'[A-Za-z0-9._+-]{1,128}',data['kernel']):raise ValueError('Invalid kernel')
                pending=[]
                for file in self.root.glob('*/submission.json'):
                    value=load(file)
                    if value['owner']==peer and value['state'] in ('uploading','pending'):
                        if all(value[k]==data[k] for k in required):return {'id':file.parent.name,'offset':(file.parent/value['filename']).stat().st_size,'state':value['state']}
                        pending.append(value)
                if len(pending)>=4 or sum(item['size'] for item in pending)+data['size']>2*1024**3:raise ValueError('Pending driver quota reached; ask the Server administrator to review imports')
                identifier=secrets.token_hex(16);folder=self.directory(identifier);folder.mkdir(mode=0o700)
                atomic(folder/data['filename'],b'');dump(folder/'submission.json',{**data,'owner':peer,'state':'uploading','created':time.time()})
                return {'id':identifier,'offset':0,'state':'uploading'}
            folder=self.directory(data['id']);value=load(folder/'submission.json')
            if value['owner']!=peer:raise ValueError('Driver submission belongs to another Client')
            file=folder/value['filename']
            if action=='status':return {'id':folder.name,'offset':file.stat().st_size,'state':value['state']}
            if value['state']!='uploading':raise ValueError('Driver submission is no longer writable')
            if action=='chunk':
                block=base64.b64decode(data['content'],validate=True);offset=data['offset']
                if type(offset) is not int or offset<0 or not 0<len(block)<=CHUNK or offset+len(block)>value['size']:raise ValueError('Invalid driver chunk')
                with file.open('r+b') as out:
                    if offset<file.stat().st_size:
                        out.seek(offset)
                        if out.read(len(block))!=block:raise ValueError('Conflicting repeated driver chunk')
                    elif offset==file.stat().st_size:
                        out.seek(offset);out.write(block);out.flush();os.fsync(out.fileno())
                    else:raise ValueError('Driver chunk is out of order')
                return {'offset':file.stat().st_size}
            if action=='finish':
                if file.stat().st_size!=value['size'] or sha256(file)!=value['sha256']:raise ValueError('Driver upload failed integrity verification')
                record=inspect(file,value['kernel'],value['hardware_ids'],value['provenance'])
                dump(folder/'record.json',record);value['state']='pending';dump(folder/'submission.json',value)
                return {'id':folder.name,'state':'pending','message':'Awaiting Server administrator approval'}
            raise ValueError('Unknown driver import action')
    def review(self,identifier,allow):
        with open(self.root/'uploads.lock','a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            folder=self.directory(identifier);value=load(folder/'submission.json')
            if value['state']!='pending':raise ValueError('Only completed pending imports can be reviewed')
            if allow:
                file=folder/value['filename'];record=inspect(file,value['kernel'],value['hardware_ids'],value['provenance'])
                approve(self.authority.database.parent/'approved-drivers',file,record)
            value['state']='approved' if allow else 'rejected';dump(folder/'submission.json',value)
            return {'id':identifier,'state':value['state']}
    def listing(self):
        return [{'id':p.parent.name,**load(p)} for p in self.root.glob('*/submission.json')]


def submit(server,credentials,file,record):
    from control_transport import request
    credentials=Path(credentials);file=Path(file)
    metadata={key:record[key] for key in ('filename','size','sha256','kernel','hardware_ids','provenance')}
    job=request(server,'/v2/drivers/begin',metadata,credentials)
    if job['state']!='uploading':return job
    with file.open('rb') as stream:
        stream.seek(job['offset']);offset=job['offset']
        while block:=stream.read(CHUNK):
            reply=request(server,'/v2/drivers/chunk',{'id':job['id'],'offset':offset,'content':base64.b64encode(block).decode()},credentials)
            offset=reply['offset']
    return request(server,'/v2/drivers/finish',{'id':job['id']},credentials)
