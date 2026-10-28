"""Small certificate-authenticated JSON transport for fixed httpboot operations."""
import http.client
import json
import os
import re
import ssl
import tempfile
import threading
import time
import collections
import ipaddress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from common import atomic, dump, load, run

MAX_BODY = 8 * 1024 * 1024

def identity(value):
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', value):
        raise ValueError('Invalid control identity')
    return value


def certificate_host(host):
    """Validate an address before interpolating it into OpenSSL configuration."""
    if not isinstance(host,str) or not host or len(host)>253:
        raise ValueError('Use a DNS hostname or IP address')
    try:
        address=ipaddress.ip_address(host)
        if '%' in host:raise ValueError('Scoped IP addresses are not certificate names')
        return 'IP',str(address)
    except ValueError:
        labels=host.removesuffix('.').split('.')
        if not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',label) for label in labels):
            raise ValueError('Use a DNS hostname or IP address')
        return 'DNS',host.lower()

def ca(folder, host):
    kind,host=certificate_host(host)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not (folder/'ca.pem').exists():
        run(['openssl','req','-x509','-newkey','rsa:3072','-nodes','-days','3650',
             '-subj','/CN=httpboot control CA','-keyout',folder/'ca.key','-out',folder/'ca.pem'],capture_output=True)
    if not (folder/'server.pem').exists():
        run(['openssl','req','-new','-newkey','rsa:3072','-nodes','-subj','/CN='+host,
             '-keyout',folder/'server.key','-out',folder/'server.csr'],capture_output=True)
        atomic(folder/'server.ext',f'subjectAltName={kind}:{host}\nextendedKeyUsage=serverAuth\n')
        run(['openssl','x509','-req','-in',folder/'server.csr','-CA',folder/'ca.pem','-CAkey',folder/'ca.key',
             '-CAcreateserial','-days','1825','-extfile',folder/'server.ext','-out',folder/'server.pem'],capture_output=True)
    for name in ('ca.key','server.key'):
        (folder/name).chmod(0o600)

def issue(folder, csr, name):
    identity(name)
    # Do not copy requester extensions or subject. The issuer assigns identity.
    with tempfile.TemporaryDirectory(dir=folder) as temp:
        tmp=Path(temp);atomic(tmp/'request',csr)
        atomic(tmp/'ext','extendedKeyUsage=clientAuth\n')
        run(['openssl','x509','-req','-in',tmp/'request','-CA',folder/'ca.pem','-CAkey',folder/'ca.key',
             '-CAcreateserial','-days','1825','-subj','/CN='+name,'-extfile',tmp/'ext','-out',tmp/'cert'],capture_output=True)
        return (tmp/'cert').read_text()

def key_request(folder, name):
    identity(name);folder.mkdir(parents=True,exist_ok=True,mode=0o700)
    if not (folder/'client.key').exists():
        run(['openssl','req','-new','-newkey','rsa:3072','-nodes','-subj','/CN='+name,
             '-keyout',folder/'client.key','-out',folder/'client.csr'],capture_output=True)
        (folder/'client.key').chmod(0o600)
    if not (folder/'client.csr').exists():
        run(['openssl','req','-new','-key',folder/'client.key','-subj','/CN='+name,'-out',folder/'client.csr'],capture_output=True)
    return (folder/'client.csr').read_text()

_pool_lock=threading.Lock()
_pool=collections.OrderedDict()

def request(url, path, data=None, credentials=None, ca_file=None, timeout=30):
    parsed=urlsplit(url)
    if parsed.scheme!='https' or parsed.username or parsed.password or parsed.path not in ('','/'):
        raise ValueError('Control requires certificate-verified HTTPS')
    ca_path=Path(ca_file or credentials/'ca.pem')
    paths=[ca_path]
    if credentials and (credentials/'client.pem').exists():paths += [credentials/'client.pem',credentials/'client.key']
    # Changing credentials immediately invalidates reuse, including enrollment.
    key=(url,timeout,tuple((str(p.resolve()),p.stat().st_mtime_ns,p.stat().st_size) for p in paths))
    with _pool_lock:
        if key not in _pool:
            context=ssl.create_default_context(cafile=str(ca_path))
            if len(paths)>1:context.load_cert_chain(paths[1],paths[2])
            _pool[key]=(context,[])
        context,idle=_pool[key];connection=None
        while idle:
            candidate,used=idle.pop()
            if time.monotonic()-used<15:connection=candidate;break
            candidate.close()
        _pool.move_to_end(key)
        while len(_pool)>8:
            _,(_,stale)=_pool.popitem(last=False)
            for old,_ in stale:old.close()
    if connection is None:connection=http.client.HTTPSConnection(parsed.hostname,parsed.port or 443,context=context,timeout=timeout)
    reusable=False
    try:
        payload=json.dumps(data).encode() if data is not None else None
        connection.request('POST' if data is not None else 'GET',path,payload,{'Content-Type':'application/json'})
        response=connection.getresponse();body=response.read(MAX_BODY+1)
        if len(body)>MAX_BODY:raise ValueError('Control response too large')
        if response.status!=200:raise ValueError(f'Control HTTP {response.status}: '+body.decode(errors='replace')[:300])
        value=json.loads(body);reusable=not response.will_close
        return value
    finally:
        # Never replay a POST after a lost response: its mutation may have committed.
        with _pool_lock:
            if reusable and key in _pool and len(_pool[key][1])<4:_pool[key][1].append((connection,time.monotonic()))
            else:connection.close()

class Handler(BaseHTTPRequestHandler):
    protocol_version="HTTP/1.1"
    def log_message(self,*args):pass
    def do_GET(self):self.respond()
    def do_POST(self):self.respond()
    def respond(self):
        self.connection.settimeout(30)
        try:
            cert=self.connection.getpeercert()
            names=[v for rdn in cert.get('subject',()) for k,v in rdn if k=='commonName'] if cert else []
            peer=names[0] if len(names)==1 else None
            if hasattr(self.server.app,'verify_certificate') and peer:
                self.server.app.verify_certificate(peer,self.connection.getpeercert(binary_form=True))
            size=int(self.headers.get('Content-Length','0'))
            if not 0<=size<=MAX_BODY:raise ValueError('Request too large')
            if self.path=='/v1/boot-report' and size>256*1024:raise ValueError('Boot report too large')
            data=json.loads(self.rfile.read(size)) if size else None
            result=self.server.app(self.command,self.path,peer,self.client_address[0],data)
            raw=json.dumps(result).encode();self.send_response(200)
        except (ValueError,OSError,KeyError,TypeError) as exc:
            self.close_connection=True
            raw=json.dumps({'error':str(exc)}).encode();self.send_response(400)
        self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)))
        self.end_headers();self.wfile.write(raw)

class TLSHTTPServer(ThreadingHTTPServer):
    """Bound slow TLS handshakes without blocking other Clients at accept()."""
    daemon_threads=True
    allow_reuse_address=True
    def __init__(self,address,handler,context,max_connections=16):
        self.context=context;self.slots=threading.BoundedSemaphore(max_connections)
        super().__init__(address,handler)
    def get_request(self):
        sock,address=super().get_request();sock.settimeout(10)
        return sock,address
    def tls_context(self):return self.context
    def process_request(self,request,address):
        if not self.slots.acquire(False):request.close();return
        try:super().process_request(request,address)
        except BaseException:self.slots.release();raise
    def process_request_thread(self,request,address):
        try:
            try:secured=self.tls_context().wrap_socket(request,server_side=True)
            except (OSError,ssl.SSLError):request.close();return
            super().process_request_thread(secured,address)
        finally:self.slots.release()


class Server(TLSHTTPServer):
    def __init__(self,address,folder,app,handler=Handler):
        self.app=app
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(folder/'server.pem',folder/'server.key')
        context.load_verify_locations(folder/'trusted-clients.pem' if (folder/'trusted-clients.pem').exists() else folder/'ca.pem')
        # No certificate is allowed only for initial IP-authorized enrollment.
        # Every other endpoint enforces its assigned certificate identity.
        context.verify_mode=ssl.CERT_OPTIONAL
        self.folder=folder;self.certificate_stamp=(folder/'server.pem').stat().st_mtime_ns;self.context_lock=threading.Lock()
        super().__init__(address,handler,context)
    def tls_context(self):
        with self.context_lock:
            stamp=(self.folder/'server.pem').stat().st_mtime_ns
            if stamp!=self.certificate_stamp:
                self.context.load_cert_chain(self.folder/'server.pem',self.folder/'server.key');self.certificate_stamp=stamp
            return self.context
