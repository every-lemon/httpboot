"""Additive Server policy for capable Clients; no device authentication shortcuts."""
from urllib.parse import urlsplit
from control_transport import certificate_host

FLATHUB='https://flathub.org/repo/flathub.flatpakrepo'
DEFAULT={'schema':1,'automatic_staging':True,'safe_repairs':True,'allowed_origins':[],'preferred_origin':None}


def validate(value):
    if not isinstance(value,dict) or set(value)-set(DEFAULT):raise ValueError('Unknown Client policy field')
    result={**DEFAULT,**value}
    if result['schema']!=1:raise ValueError('Unsupported Client policy schema')
    for key in ('automatic_staging','safe_repairs'):
        if type(result[key]) is not bool:raise ValueError('Policy switches must be boolean')
    origins=result['allowed_origins']
    if not isinstance(origins,list) or len(origins)>16:raise ValueError('Use at most 16 Server origins')
    normalized=[]
    for origin in origins:
        if not isinstance(origin,str):raise ValueError('Invalid Server origin')
        url=urlsplit(origin)
        if url.scheme!='https' or not url.hostname or url.username or url.password or url.path not in ('','/') or url.query or url.fragment:
            raise ValueError('Server origins must be HTTPS addresses without paths or credentials')
        certificate_host(url.hostname)
        if url.port is not None and not 1<=url.port<=65535:raise ValueError('Invalid Server port')
        normalized.append(origin.rstrip('/'))
    result['allowed_origins']=list(dict.fromkeys(normalized))
    preferred=result['preferred_origin']
    if preferred is not None and preferred not in result['allowed_origins']:raise ValueError('Preferred Server must be an allowed origin')
    return result


def extend_transport_certificate(folder,origins):
    """Add transport aliases with the same key/CA, retaining every old SAN.

    Keeping old names preserves older Clients and signed offline manifests.
    The running transport reloads the certificate on its next connection.
    """
    import ipaddress,re,subprocess,tempfile
    from pathlib import Path
    from common import atomic
    folder=Path(folder)
    if not origins:return
    certificate=folder/'server.pem'
    existing=subprocess.run(['openssl','x509','-in',str(certificate),'-noout','-ext','subjectAltName'],check=True,capture_output=True,text=True).stdout
    names=set()
    for kind,name in re.findall(r'(DNS|IP Address):([^,\s]+)',existing):names.add(('DNS' if kind=='DNS' else 'IP',name))
    old=set(names)
    for origin in origins:
        host=urlsplit(origin).hostname
        kind,host=certificate_host(host)
        names.add((kind,host))
    if names==old:return
    with tempfile.TemporaryDirectory(dir=folder) as temporary:
        work=Path(temporary)
        subprocess.run(['openssl','x509','-x509toreq','-in',str(certificate),'-signkey',str(folder/'server.key'),'-out',str(work/'request')],check=True,capture_output=True)
        atomic(work/'extensions','subjectAltName='+','.join(kind+':'+name for kind,name in sorted(names))+'\nextendedKeyUsage=serverAuth\n')
        subprocess.run(['openssl','x509','-req','-in',str(work/'request'),'-CA',str(folder/'ca.pem'),'-CAkey',str(folder/'ca.key'),'-CAcreateserial','-days','1825','-extfile',str(work/'extensions'),'-out',str(work/'certificate')],check=True,capture_output=True)
        subprocess.run(['openssl','verify','-CAfile',str(folder/'ca.pem'),'-purpose','sslserver',str(work/'certificate')],check=True,capture_output=True)
        backup=folder/'server-before-origins.pem'
        if not backup.exists():atomic(backup,certificate.read_bytes())
        atomic(certificate,(work/'certificate').read_bytes())


def select_origin(default,identity):
    from pathlib import Path
    from common import load
    from control_transport import request
    identity=Path(identity);path=identity/'server-origins.json'
    if not path.is_file() or not (identity/'client.pem').is_file():return default
    try:policy=validate(load(path))
    except (OSError,ValueError,TypeError):return default
    candidates=list(dict.fromkeys([policy.get('preferred_origin'),default,*policy['allowed_origins']]))
    for origin in [value for value in candidates if value][:3]:
        try:
            request(origin,'/v2/health',credentials=identity,timeout=5)
            return origin
        except (OSError,ValueError):pass
    return default
