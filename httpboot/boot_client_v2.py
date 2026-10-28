"""Common activation and verified image download used by HTTP and removable startup."""
import argparse
import base64
import json
import subprocess
import tempfile
import time
from pathlib import Path
from common import atomic,dump,load,recovery_size_ok,sha256
from control_transport import key_request,request
from image_delivery import download


def verify_manifest(value,ca,server):
    payload={key:item for key,item in value.items() if key not in ('signature','signer')}
    with tempfile.TemporaryDirectory() as temporary:
        folder=Path(temporary);atomic(folder/'cert',value['signer'])
        # The enrolled deployment CA authorizes the image signer independently
        # of transport aliases. Client certificates have clientAuth only and
        # cannot sign images. HTTPS still verifies the actual connection name.
        subprocess.run(['openssl','verify','-CAfile',str(ca),'-purpose','sslserver',str(folder/'cert')],check=True,capture_output=True)
        public=subprocess.run(['openssl','x509','-in',str(folder/'cert'),'-pubkey','-noout'],check=True,capture_output=True).stdout
        atomic(folder/'public',public);atomic(folder/'signature',base64.b64decode(value['signature'],validate=True))
        subprocess.run(['openssl','dgst','-sha256','-verify',str(folder/'public'),'-signature',str(folder/'signature')],
                       input=json.dumps(payload,sort_keys=True,separators=(',',':')).encode(),check=True,capture_output=True)
    return payload


def hardware():
    import os
    values={'architecture':os.uname().machine}
    for name in ('product_uuid','product_name','board_name'):
        file=Path('/sys/class/dmi/id')/name
        if file.is_file():values[name]=file.read_text().strip()[:256]
    return values


def activate(server,identity,ca,display=print):
    identity=Path(identity);identity.mkdir(parents=True,exist_ok=True,mode=0o700)
    atomic(identity/'ca.pem',Path(ca).read_bytes())
    if (identity/'client.pem').exists():
        request(server,'/v2/health',credentials=identity)
        current=subprocess.run(['openssl','verify','-CAfile',str(identity/'ca.pem'),'-purpose','sslclient',str(identity/'client.pem')],capture_output=True)
        if current.returncode:
            csr=key_request(identity,'httpboot-client')
            renewed=request(server,'/v2/renew',{'csr':csr},identity)
            atomic(identity/'client.pem',renewed['certificate'])
        request(server,'/v2/hardware',hardware(),identity)
        send_reports(server,identity)
        return True
    csr=key_request(identity,'httpboot-client')
    from boot_identity import persist_credentials
    persist_credentials(identity)
    response=request(server,'/v2/activation',{'csr':csr,'hardware':hardware()},identity)
    if not response.get('approved'):
        display('Please configure your server to allow this client.\nPairing code: '+response['code']+' (valid for ten minutes)')
        return False
    atomic(identity/'client.pem',response['certificate'])
    send_reports(server,identity)
    return True


def send_reports(server,identity):
    for folder in (Path('/run/httpboot-v2/reports'),identity/'reports'):
        for file in sorted(folder.glob('*.json'))[:100]:
            try:
                from boot_reports import sanitize
                request(server,'/v2/diagnostics',sanitize(load(file)),identity);file.unlink()
            except Exception:break


def offline(identity,ca,server,output):
    from recovery_cache import selected
    identity=Path(identity);cache=selected(identity);manifest=load(cache/'verified-image.json')
    # A previously approved identity and a signed Server manifest are both required.
    subprocess.run(['openssl','verify','-CAfile',str(ca),'-purpose','sslclient',str(identity/'client.pem')],check=True,capture_output=True)
    verify_manifest(manifest,ca,server)
    private_public=subprocess.run(['openssl','pkey','-in',str(identity/'client.key'),'-pubout'],check=True,capture_output=True).stdout
    cert_public=subprocess.run(['openssl','x509','-in',str(identity/'client.pem'),'-pubkey','-noout'],check=True,capture_output=True).stdout
    if private_public!=cert_public:raise ValueError('Offline recovery requires the approved device private key')
    if manifest.get('kernel')!=__import__('os').uname().release:
        from kernel_stage import offline_transition
        offline_transition(identity,manifest,cache)
    recovery=cache/'recovery.squashfs';meta=manifest['artifacts']['recovery.squashfs']
    recovery_size_ok(recovery.stat().st_size)
    if recovery.stat().st_size!=meta['size'] or sha256(recovery)!=meta['sha256']:
        raise ValueError('Cached recovery image failed verification')
    import shutil
    shutil.copyfile(recovery,output)
    return {'release':manifest['release'],'sha256':meta['sha256'],'size':meta['size'],'offline':True}


def fetch(server,identity,ca,output,previous=False,progress=lambda **values:None):
    route='/v2/recovery/images' if previous else '/v2/images'
    items=request(server,route,credentials=identity)['images']
    requested=next((word.split('=',1)[1] for word in Path('/proc/cmdline').read_text().split() if word.startswith('httpboot.release=')),None)
    if requested and not previous:
        items=[item for item in request(server,'/v2/recovery/images',credentials=identity)['images'] if item['release']==requested]
    if previous:
        current=request(server,'/v2/images',credentials=identity)['images']
        active={item['release'] for item in current}
        items=[item for item in items if item['release'] not in active]
    if not items:raise ValueError('No previous verified image is available' if previous else 'No validated image has been published')
    selected=items[0];verify_manifest(selected,ca,server)
    if selected.get('kernel')!=__import__('os').uname().release:
        from kernel_stage import transition
        transition(server,identity,selected,progress)
    size=selected['artifacts']['filesystem.squashfs']['size']
    memory={line.split(':')[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith(('MemAvailable:','MemTotal:'))}
    if type(size) is not int or size<=0 or size>memory['MemTotal']*3//4 or size+2*1024**3>memory['MemAvailable']:
        raise ValueError('Insufficient RAM for the advertised image and desktop startup')
    download(server,selected['release'],'filesystem.squashfs',selected['artifacts']['filesystem.squashfs'],identity,output,progress)
    request(server,'/v2/deployment',{'release':selected['release']},identity)
    dump(output.with_suffix('.manifest.json'),selected)
    return {'release':selected['release'],'sha256':selected['artifacts']['filesystem.squashfs']['sha256'],
            'size':selected['artifacts']['filesystem.squashfs']['size'],'offline':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--identity',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--previous',action='store_true');parser.add_argument('--offline',action='store_true')
    parser.add_argument('--cache-recovery',action='store_true')
    args=parser.parse_args();config=load(args.config)
    from boot_ui import Progress
    ui=Progress()
    try:
        ui.stage('Checking Client identity and Server connection')
        if args.offline:result=offline(args.identity,config['ca'],config['server'],args.output)
        else:
            from client_policy import select_origin
            config['server']=select_origin(config['server'],args.identity)
            while not activate(config['server'],args.identity,config['ca'],ui.message):time.sleep(12)
            policy=request(config['server'],'/v2/policy',credentials=args.identity).get('client_policy',{})
            dump(args.identity/'server-origins.json',policy)
            while not request(config['server'],'/v2/accounts',credentials=args.identity)['accounts']:
                from boot_reports import collect
                try:request(config['server'],'/v2/diagnostics',collect('account-assignment','accounts-missing'),args.identity)
                except Exception:pass
                ui.message('Client approved; waiting for account assignment.\nIn Server setup, open Boot health to identify this Client, then Assign account. Startup will continue automatically.')
                time.sleep(10)
            ui.stage('Downloading and verifying the Client image')
            progress=ui.progress
            from boot_reports import collect
            try:request(config['server'],'/v2/diagnostics',collect('image-download'),args.identity)
            except Exception:pass
            result=fetch(config['server'],args.identity,config['ca'],args.output,args.previous,progress)
            from recovery_cache import available,reuse
            if args.cache_recovery and not available(args.identity,load(args.output.with_suffix('.manifest.json'))):
                selected=load(args.output.with_suffix('.manifest.json'));meta=selected['artifacts']['recovery.squashfs']
                recovery_size_ok(meta['size'])
                try:
                    staging=args.identity/'recovery-downloads'/selected['release'];staging.mkdir(parents=True,exist_ok=True)
                    for name in ('recovery.squashfs','recovery.efi'):
                        ui.stage('Caching verified recovery: '+name)
                        if not reuse(args.identity,selected,name,staging/name):
                            download(config['server'],selected['release'],name,selected['artifacts'][name],args.identity,staging/name,progress)
                    from recovery_cache import publish
                    publish(args.identity,selected,staging)
                    import shutil
                    shutil.rmtree(staging)
                except Exception:
                    print('Recovery cache is unavailable; desktop startup can continue.',flush=True)
        ui.stage('Image verified; preparing Client startup')
        dump(args.output.with_suffix('.metadata.json'),result)
    except Exception as error:
        ui.close()
        from boot_reports import store,collect
        report=collect('activation-or-image','startup-failed')
        try:
            store(Path('/run/httpboot-v2/reports'),report)
            if args.cache_recovery:store(args.identity/'reports',report)
        except OSError:pass
        print('Activation Server Error: '+str(error),flush=True);raise SystemExit(1)
    finally:ui.close()

if __name__=='__main__':main()
