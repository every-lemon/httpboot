"""Authenticated immutable image catalogue and resumable mutual-TLS downloads."""
import hashlib
import http.client
import json
import os
import re
import ssl
import time
from pathlib import Path
from urllib.parse import urlsplit
from common import RELEASE, dump, load, recovery_size_ok, sha256
from control_transport import Handler

ARTIFACTS={'boot.efi','recovery.efi','recovery.squashfs','filesystem.squashfs'}


class Images:
    def __init__(self,authority):
        self.authority=authority
        self.root=authority.database.parent/'images'
        self.root.mkdir(mode=0o700,exist_ok=True)
        with authority.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS images (id TEXT PRIMARY KEY, manifest TEXT, created REAL, active INTEGER)')
            db.execute('CREATE TABLE IF NOT EXISTS image_pins (image TEXT, reason TEXT, PRIMARY KEY(image,reason))')
            for retired in self.root.glob('.retired-*'):
                identifier=retired.name.removeprefix('.retired-')
                if not RELEASE.fullmatch(identifier) or retired.is_symlink():continue
                if db.execute('SELECT 1 FROM images WHERE id=?',(identifier,)).fetchone():
                    retired.rename(self.root/identifier)
                else:
                    import shutil
                    shutil.rmtree(retired)

    def publish(self,identifier,directory,proof):
        if not RELEASE.fullmatch(identifier) or identifier in ('.','..'):
            raise ValueError('Invalid image identifier')
        directory=Path(directory).resolve(strict=True)
        proof=load(proof)
        records={}
        for name in sorted(ARTIFACTS):
            file=directory/name
            if file.is_symlink() or not file.is_file():raise ValueError('Image must have all regular artifacts')
            if name=='recovery.squashfs':recovery_size_ok(file.stat().st_size)
            records[name]={'size':file.stat().st_size,'sha256':sha256(file)}
        if proof.get('validator_sha256')!=sha256(Path(__file__).with_name('validate_v2.py')) or proof.get('schema')!=2 or proof.get('architecture')!='amd64' or any(proof.get(check) is not True for check in ('startup_verified','recovery_verified','assigned_login_verified','native_http_pairing_verified','clean_shutdown_verified')) or proof.get('artifacts')!=records:
            raise ValueError('Matching successful startup and recovery validation proof required')
        if proof.get('kernel')!=load(directory/'release.json').get('kernel'):raise ValueError('Validation proof does not match the recorded image kernel')
        with self.authority.db() as db:
            if db.execute('SELECT 1 FROM images WHERE id=?',(identifier,)).fetchone():
                raise ValueError('Published images are immutable')
            target=self.root/identifier
            target.mkdir(mode=0o700)
            import shutil
            try:
                for name,meta in records.items():
                    shutil.copyfile(directory/name,target/name)
                    if sha256(target/name)!=meta['sha256']:raise ValueError('Image copy verification failed')
                    with open(target/name,'rb') as stream:os.fsync(stream.fileno())
                info={'schema':2,'release':identifier,'architecture':'amd64','kernel':load(directory/'release.json')['kernel'],'artifacts':records}
                import base64,subprocess
                pki=self.authority.database.parent/'pki'
                signature=subprocess.run(['openssl','dgst','-sha256','-sign',str(pki/'server.key')],
                    input=json.dumps(info,sort_keys=True,separators=(',',':')).encode(),capture_output=True,check=True).stdout
                info['signature']=base64.b64encode(signature).decode();info['signer']=(pki/'server.pem').read_text()
                dump(target/'manifest.json',info)
                db.execute('UPDATE images SET active=0')
                db.execute('INSERT INTO images VALUES (?,?,?,1)',(identifier,json.dumps(info),self.authority.clock()))
            except BaseException:
                shutil.rmtree(target)
                raise
        return info

    def catalogue(self,peer,recovery=False):
        with self.authority.db(write=False) as db:
            self.authority.device(db,peer)
            query='SELECT manifest FROM images ORDER BY created DESC,id DESC' if recovery else 'SELECT manifest FROM images WHERE active=1'
            return {'schema':2,'images':[json.loads(r['manifest']) for r in db.execute(query)]}

    def open(self,peer,identifier,name):
        with self.authority.db() as db:
            self.authority.device(db,peer)
            if name not in ARTIFACTS or not RELEASE.fullmatch(identifier):raise ValueError('Unknown image artifact')
            row=db.execute('SELECT manifest FROM images WHERE id=?',(identifier,)).fetchone()
            if not row:raise ValueError('Image has not passed publication validation')
            meta=json.loads(row['manifest'])['artifacts'][name]
            path=self.root/identifier/name
            descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
            stream=os.fdopen(descriptor,'rb')
            reason='transfer:'+__import__('secrets').token_hex(16)
            db.execute('INSERT INTO image_pins VALUES (?,?)',(identifier,reason))
            if os.fstat(stream.fileno()).st_size!=meta['size']:
                stream.close();raise ValueError('Published image size changed')
            return Transfer(stream,self.authority,identifier,reason),meta


class Transfer:
    def __init__(self,stream,authority,image,reason):
        self.stream=stream;self.authority=authority;self.image=image;self.reason=reason
    def __getattr__(self,name):return getattr(self.stream,name)
    def __enter__(self):return self
    def __exit__(self,*args):
        self.stream.close()
        with self.authority.db() as db:
            db.execute('DELETE FROM image_pins WHERE image=? AND reason=?',(self.image,self.reason))


class ImageHandler(Handler):
    def do_GET(self):
        self._streaming=False
        if not self.path.startswith('/v2/image/'):
            return super().do_GET()
        self.connection.settimeout(30)
        try:
            parts=self.path.split('/')
            if len(parts)!=5:raise ValueError('Invalid image path')
            cert=self.connection.getpeercert()
            names=[v for rdn in cert.get('subject',()) for k,v in rdn if k=='commonName'] if cert else []
            peer=names[0] if len(names)==1 else None
            if peer:self.server.app.verify_certificate(peer,self.connection.getpeercert(binary_form=True))
            stream,meta=self.server.app.images.open(peer,parts[3],parts[4])
            with stream:
                offset=0
                header=self.headers.get('Range')
                if header:
                    match=re.fullmatch(r'bytes=(\d+)-',header)
                    if not match or int(match[1])>=meta['size']:raise ValueError('Invalid download range')
                    offset=int(match[1])
                self.send_response(206 if header else 200)
                self.send_header('Content-Type','application/octet-stream')
                self.send_header('Content-Length',str(meta['size']-offset))
                self.send_header('ETag','"'+meta['sha256']+'"')
                self.send_header('Accept-Ranges','bytes')
                if header:self.send_header('Content-Range',f"bytes {offset}-{meta['size']-1}/{meta['size']}")
                self.end_headers();self._streaming=True;stream.seek(offset)
                while True:
                    block=stream.read(1024*1024)
                    if not block:break
                    self.wfile.write(block)
        except (ValueError,OSError) as error:
            # Do not expose private filesystem paths or issue a second response after headers.
            if not getattr(self,'_streaming',False):
                try:self.send_error(403,'Approved Client and validated artifact required')
                except OSError:pass


def download(url,release,name,meta,credentials,target,progress=lambda **values:None):
    if name not in ARTIFACTS or not RELEASE.fullmatch(release):raise ValueError('Invalid artifact request')
    parsed=urlsplit(url)
    if parsed.scheme!='https' or parsed.username or parsed.password or parsed.path not in ('','/'):
        raise ValueError('Image transfer requires a verified HTTPS Server origin')
    target=Path(target);partial=target.with_name(target.name+'.partial')
    target.parent.mkdir(parents=True,exist_ok=True)
    if target.is_file() and sha256(target)==meta['sha256']:return target
    offset=partial.stat().st_size if partial.exists() else 0
    if offset>meta['size']:partial.unlink();offset=0
    if offset==meta['size'] and sha256(partial)==meta['sha256']:
        os.replace(partial,target);return target
    if offset==meta['size']:partial.unlink();offset=0
    context=ssl.create_default_context(cafile=str(credentials/'ca.pem'))
    context.load_cert_chain(credentials/'client.pem',credentials/'client.key')
    connection=http.client.HTTPSConnection(parsed.hostname,parsed.port or 443,context=context,timeout=30)
    started=time.monotonic();done=offset
    try:
        connection.request('GET',f'/v2/image/{release}/{name}',headers={'Range':f'bytes={offset}-'} if offset else {})
        response=connection.getresponse()
        if response.status!=(206 if offset else 200):raise ValueError(f'Authenticated image download failed: HTTP {response.status}')
        if response.getheader('ETag')!='"'+meta['sha256']+'"':raise ValueError('Image checksum identity changed')
        if offset and response.getheader('Content-Range')!=f"bytes {offset}-{meta['size']-1}/{meta['size']}":
            raise ValueError('Server returned the wrong resume range')
        with open(partial,'ab' if offset else 'wb') as out:
            while True:
                block=response.read(min(1024*1024,meta['size']-done+1))
                if not block:break
                done+=len(block)
                if done>meta['size']:raise ValueError('Image exceeds advertised size')
                out.write(block)
                elapsed=max(0.001,time.monotonic()-started);speed=(done-offset)/elapsed
                progress(bytes_done=done,bytes_total=meta['size'],bytes_per_second=speed,
                         elapsed_seconds=elapsed,eta_seconds=(meta['size']-done)/speed if speed else None)
            out.flush();os.fsync(out.fileno())
        if done!=meta['size'] or sha256(partial)!=meta['sha256']:raise ValueError('Image download failed verification; partial transfer retained')
        os.replace(partial,target)
        return target
    finally:connection.close()
