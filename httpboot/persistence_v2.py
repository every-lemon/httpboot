"""Changed-content saves over the authenticated Server protocol; no NFS authority."""
import base64
import ctypes
import hashlib
import fcntl
import functools
import struct
import json
import os
import select
import sqlite3
import stat
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from snapshot_store import CHUNK_SIZE, relative, manifest, needs_clean


def identity(st):
    return [st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns,stat.S_IMODE(st.st_mode)&0o700]


class Home:
    """All descendant opens are relative to directory FDs and reject symlinks."""
    def __init__(self,path,owner=None):
        self.path=Path(path);self.owner=os.getuid() if owner is None else owner

    @contextmanager
    def directory(self,value,create=False):
        relative(value)
        fd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            for part in value.split('/'):
                if create:
                    try:os.mkdir(part,0o700,dir_fd=fd)
                    except FileExistsError:pass
                next_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd);fd=next_fd
            yield fd
        finally:os.close(fd)

    def walk(self,folder,allow_links=False):
        def descend(fd,prefix=''):
            for name in sorted(os.listdir(fd)):
                path=prefix+name
                st=os.stat(name,dir_fd=fd,follow_symlinks=False)
                if stat.S_ISLNK(st.st_mode):
                    if not allow_links:raise ValueError('Selected folder contains a symlink; save refused')
                    if st.st_uid!=self.owner:raise ValueError('Selected folder contains a link owned by another account')
                    # Chromium/Electron singleton links point to process-local
                    # sockets/locks. They must be recreated by the application.
                    profile=folder in ('.config/google-chrome','.config/ChatGPT','.config/chatgpt','.config/Codex')
                    if profile and not prefix and name in ('SingletonSocket','SingletonLock','SingletonCookie'):continue
                    target=os.readlink(name,dir_fd=fd)
                    if os.path.isabs(target):
                        base=os.path.abspath(self.path/folder);candidate=os.path.normpath(target)
                        if os.path.commonpath((base,candidate))==base:
                            target=os.path.relpath(candidate,os.path.join(base,os.path.dirname(path)))
                    yield path,{'link':target};continue
                if stat.S_ISDIR(st.st_mode):
                    # Codex recreates these executable shims on every launch.
                    if folder=='.codex' and path in ('tmp/arg0','tmp/arg0-linux'):
                        if st.st_uid!=self.owner:raise ValueError('Runtime directory belongs to another account')
                        continue
                    child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                    try:yield from descend(child,path+'/')
                    finally:os.close(child)
                elif stat.S_ISREG(st.st_mode):
                    if st.st_uid!=self.owner:raise ValueError('Selected folder contains a file owned by another account')
                    yield path,identity(st)
                elif stat.S_ISSOCK(st.st_mode):
                    # Unix sockets are live IPC endpoints, never durable data.
                    if st.st_uid!=self.owner:raise ValueError('Selected folder contains a socket owned by another account')
                    continue
                else:raise ValueError('Selected folder contains a socket or special file; save refused')
        with self.directory(folder,create=True) as fd:yield from descend(fd)

    @contextmanager
    def file(self,folder,path):
        relative(path)
        parent=str(Path(path).parent)
        directory=folder+('/'+parent if parent!='.' else '')
        with self.directory(directory) as fd:
            file_fd=os.open(Path(path).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            try:
                current=os.fstat(file_fd)
                if not stat.S_ISREG(current.st_mode) or current.st_uid!=self.owner:raise ValueError('File changed ownership or became a special file')
                with os.fdopen(file_fd,'rb',closefd=False) as stream:yield stream
            finally:os.close(file_fd)

    def restore_file(self,folder,path,chunks,fetch,size,mode=0o600):
        relative(path)
        parent=str(Path(path).parent)
        with self.directory(folder+('/'+parent if parent!='.' else ''),create=True) as fd:
            temporary='.httpboot-'+__import__('secrets').token_hex(12)
            out_fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            try:
                os.fchmod(out_fd,mode)
                count=0
                with os.fdopen(out_fd,'wb') as out:
                    for digest in chunks:
                        block=fetch(digest)
                        if hashlib.sha256(block).hexdigest()!=digest:raise ValueError('Restore checksum mismatch')
                        out.write(block);count+=len(block)
                    if count!=size:raise ValueError('Restore file size mismatch')
                    out.flush();os.fsync(out.fileno())
                os.replace(temporary,Path(path).name,src_dir_fd=fd,dst_dir_fd=fd)
                os.fsync(fd)
            finally:
                try:os.unlink(temporary,dir_fd=fd)
                except FileNotFoundError:pass

    def prune(self,folder,files):
        directories={str(parent) for name in files for parent in Path(name).parents if str(parent)!='.'}
        def visit(fd,prefix=''):
            for name in os.listdir(fd):
                path=prefix+name;info=os.stat(name,dir_fd=fd,follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                    try:visit(child,path+'/')
                    finally:os.close(child)
                    if path not in directories:os.rmdir(name,dir_fd=fd)
                elif path not in files:os.unlink(name,dir_fd=fd)
        with self.directory(folder,create=True) as fd:visit(fd)

    def restore_link(self,folder,path,target):
        parent=str(Path(path).parent)
        with self.directory(folder+('/'+parent if parent!='.' else ''),create=True) as fd:
            temporary='.httpboot-link-'+__import__('secrets').token_hex(12)
            os.symlink(target,temporary,dir_fd=fd)
            try:
                os.replace(temporary,Path(path).name,src_dir_fd=fd,dst_dir_fd=fd);os.fsync(fd)
            finally:
                try:os.unlink(temporary,dir_fd=fd)
                except FileNotFoundError:pass


def serialized(method):
    @functools.wraps(method)
    def guarded(self,*args,**kwargs):
        with open(self.cache.with_suffix('.lock'),'a') as guard:
            deadline=time.monotonic()+120
            while True:
                try:fcntl.flock(guard,fcntl.LOCK_EX|fcntl.LOCK_NB);break
                except BlockingIOError:
                    if time.monotonic()>=deadline:raise TimeoutError('Saver did not drain within 120 seconds; RAM work and previous snapshots are retained')
                    time.sleep(0.1)
            return method(self,*args,**kwargs)
    return guarded


class Saver:
    def __init__(self,home,cache,call,status=lambda **values:None):
        self.home=Home(home);self.call=call;self.status=status;self.last_verified={}
        self.cache=Path(cache);self.cache.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with self.db() as db:db.execute('CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, identity TEXT, chunks TEXT)')
        self.cache.chmod(0o600)

    @contextmanager
    def db(self):
        connection=sqlite3.connect(self.cache,timeout=120)
        try:
            with connection:yield connection
        finally:connection.close()

    def chunks(self,folder,path,expected):
        key=folder+'/'+path
        with self.db() as db:
            row=db.execute('SELECT identity,chunks FROM files WHERE path=?',(key,)).fetchone()
        if row and json.loads(row[0])==expected:return json.loads(row[1])
        hashes=[]
        with self.home.file(folder,path) as stream:
            if identity(os.fstat(stream.fileno()))!=expected:raise ValueError('File changed before save')
            while True:
                block=stream.read(CHUNK_SIZE)
                if not block:break
                hashes.append(hashlib.sha256(block).hexdigest())
            if identity(os.fstat(stream.fileno()))!=expected:raise ValueError('File changed during save')
        with self.db() as db:db.execute('INSERT OR REPLACE INTO files VALUES (?,?,?)',(key,json.dumps(expected),json.dumps(hashes)))
        return hashes

    @serialized
    def save(self,rule,closed=lambda:True):
        folder=rule['folder']
        clean_required=needs_clean(rule)
        if clean_required and not closed():raise ValueError('Waiting for the application to close; previous verified save retained')
        before=dict(self.home.walk(folder,allow_links=True));files={};locations={}
        for path,info in before.items():
            if isinstance(info,dict):files[path]=info;continue
            hashes=self.chunks(folder,path,info)
            files[path]={'size':info[2],'chunks':hashes,'mode':info[5]}
            for index,digest in enumerate(hashes):locations[digest]=(path,index)
        hashes=list(locations)
        manifest(files)
        missing=[]
        for start in range(0,len(hashes),4096):
            missing.extend(self.call('missing',{'hashes':hashes[start:start+4096]})['missing'])
        for count,digest in enumerate(missing,1):
            path,index=locations[digest]
            with self.home.file(folder,path) as stream:
                if identity(os.fstat(stream.fileno()))!=before[path]:raise ValueError('File changed before transfer')
                stream.seek(index*CHUNK_SIZE);content=stream.read(CHUNK_SIZE)
            if hashlib.sha256(content).hexdigest()!=digest:raise ValueError('File changed during transfer')
            self.call('put',{'digest':digest,'content':base64.b64encode(content).decode()})
            self.status(folder=folder,phase='transferring',chunks_done=count,chunks_total=len(missing))
        if dict(self.home.walk(folder,allow_links=True))!=before:raise ValueError('Folder changed during save; pending changes retained')
        if clean_required and not closed():raise ValueError('Application reopened; previous verified save retained')
        if len(json.dumps(files))>2*1024**2:
            stage=self.call('begin',{'folder':folder})['stage'];page={};size=0
            for name,record in files.items():
                entry_size=len(json.dumps({name:record}))
                if page and size+entry_size>2*1024**2:
                    self.call('stage',{'stage':stage,'files':page});page={};size=0
                page[name]=record;size+=entry_size
            if page:self.call('stage',{'stage':stage,'files':page})
            result=self.call('commit',{'stage':stage,'app_closed':clean_required})
        else:result=self.call('commit',{'folder':folder,'files':files,'app_closed':clean_required})
        self.last_verified[folder]=before
        self.status(folder=folder,phase='verified',snapshot=result['id'],updated=time.time())
        return result

    def stable(self,rule):
        return rule['folder'] in self.last_verified and dict(self.home.walk(rule['folder'],allow_links=True))==self.last_verified[rule['folder']]

    @serialized
    def restore(self,rule,snapshot_id=None):
        folder=rule['folder'];value={'folder':folder}
        if snapshot_id is not None:value['snapshot']=snapshot_id
        snapshot=self.call('latest',value)['snapshot']
        if not snapshot:return
        files={};offset=0
        while True:
            page=self.call('manifest-page',{'folder':folder,'id':snapshot['id'],'offset':offset})
            files.update(page['files'])
            if page['next'] is None:break
            offset=page['next']
        files=manifest(files)
        # Restore is only called before the user's desktop is allowed to start.
        from concurrent.futures import ThreadPoolExecutor,wait,FIRST_COMPLETED
        started=time.monotonic();done=0;total=sum(record.get('size',0) for record in files.values())
        self.status(folder=folder,phase='restoring',bytes_done=0,bytes_total=total)
        def restore_one(item):
            path,record=item
            key=folder+'/'+path
            try:
                with self.home.file(folder,path) as stream:current=identity(os.fstat(stream.fileno()))
                with self.db() as db:cached=db.execute('SELECT identity,chunks FROM files WHERE path=?',(key,)).fetchone()
                if cached and json.loads(cached[0])==current and json.loads(cached[1])==record['chunks'] and current[2]==record['size'] and current[5]==record.get('mode',0o600):return record['size']
            except OSError as error:
                import errno
                if error.errno not in (errno.ENOENT,errno.ELOOP):raise
            self.home.restore_file(folder,path,record['chunks'],
                lambda digest:base64.b64decode(self.call('get',{'digest':digest})['content'],validate=True),record['size'],record.get('mode',0o600))
            with self.home.file(folder,path) as stream:current=identity(os.fstat(stream.fileno()))
            with self.db() as db:db.execute('INSERT OR REPLACE INTO files VALUES (?,?,?)',(key,json.dumps(current),json.dumps(record['chunks'])))
            return record['size']
        # Bound both workers and queued jobs; large manifests cannot exhaust RAM.
        entries=iter((path,record) for path,record in files.items() if 'link' not in record)
        with ThreadPoolExecutor(max_workers=4) as pool:
            pending=set()
            while True:
                while len(pending)<4:
                    item=next(entries,None)
                    if item is None:break
                    pending.add(pool.submit(restore_one,item))
                if not pending:break
                completed,pending=wait(pending,return_when=FIRST_COMPLETED)
                for future in completed:done+=future.result()
                elapsed=max(time.monotonic()-started,0.001);speed=done/elapsed
                self.status(folder=folder,phase='restoring',bytes_done=done,bytes_total=total,
                            speed=speed,elapsed_seconds=elapsed,eta_seconds=(total-done)/speed if speed else None)
        for path,record in files.items():
            if 'link' in record:self.home.restore_link(folder,path,record['link'])
        # Only after every replacement verifies, remove stale files from a previous
        # clean login. Failed logout sessions bypass restore and retain their RAM.
        self.home.prune(folder,files)


class Watcher:
    """Recursive inotify notifications; hashing happens after a two-second quiet period."""
    MASK=0x00000fff  # access/open are filtered below; include directory creation/move.
    def __init__(self,paths):
        self.lib=ctypes.CDLL(None,use_errno=True)
        self.fd=self.lib.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
        if self.fd<0:raise OSError(ctypes.get_errno(),'inotify initialization failed')
        self.paths=[Path(p) for p in paths];self.watches={}
        self.refresh()

    def refresh(self):
        known=set(self.watches.values())
        for root in self.paths:
            root.mkdir(parents=True,exist_ok=True,mode=0o700)
            for folder,dirs,files in os.walk(root,followlinks=False):
                dirs[:]=[d for d in dirs if not (Path(folder)/d).is_symlink()]
                if folder in known:continue
                # Modify, attrib, close-write, move, create, delete; do not watch reads.
                wd=self.lib.inotify_add_watch(self.fd,os.fsencode(folder),0x00000fce)
                if wd<0:raise OSError(ctypes.get_errno(),'Unable to watch selected folder')
                self.watches[wd]=folder;known.add(folder)

    def changed_roots(self,timeout=1):
        if not select.select([self.fd],[],[],timeout)[0]:return set()
        changed=set()
        while True:
            try:
                events=os.read(self.fd,256*1024)
                if not events:break
                offset=0
                while offset+16<=len(events):
                    wd,mask,cookie,length=struct.unpack_from('iIII',events,offset);offset+=16+length
                    folder=self.watches.get(wd)
                    if folder:
                        for root in self.paths:
                            if Path(folder)==root or root in Path(folder).parents:changed.add(root)
                    if mask&0x8000:self.watches.pop(wd,None)
                    if mask&0x4000:self.watches.clear();changed.update(self.paths)
            except BlockingIOError:break
        self.refresh()
        return changed

    def changed(self,timeout=1):return bool(self.changed_roots(timeout))

    def close(self):os.close(self.fd)
