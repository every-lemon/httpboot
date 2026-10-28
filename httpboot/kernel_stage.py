"""One bounded startup transition to a newer image's matching verified kernel."""
import gzip
import hashlib
import json
import os
import struct
import subprocess
import tempfile
from pathlib import Path
from common import atomic
from image_delivery import download


def sections(path):
    data=Path(path).read_bytes()
    if len(data)<64 or data[:2]!=b'MZ':raise ValueError('Invalid verified EFI header')
    offset=struct.unpack_from('<I',data,0x3c)[0]
    if offset+24>len(data) or data[offset:offset+4]!=b'PE\0\0':raise ValueError('Invalid verified EFI signature')
    machine,count,_,_,_,optional,_=struct.unpack_from('<HHIIIHH',data,offset+4)
    if machine!=0x8664 or not 0<count<=96:raise ValueError('Expected an amd64 EFI image')
    start=offset+24+optional;result={}
    for number in range(count):
        header=start+number*40
        if header+40>len(data):raise ValueError('Truncated EFI section table')
        name=data[header:header+8].rstrip(b'\0').decode('ascii')
        size,_,raw_size,raw_offset=struct.unpack_from('<IIII',data,header+8)
        if size>raw_size or raw_offset+size>len(data):raise ValueError('Truncated EFI payload')
        if name in ('.linux','.initrd','.cmdline'):
            if name in result:raise ValueError('Duplicate EFI payload')
            result[name]=data[raw_offset:raw_offset+size]
    if not {'.linux','.initrd','.cmdline'}<=set(result):raise ValueError('EFI kernel payload is incomplete')
    return result


def identity_overlay(identity):
    output=bytearray();inode=1
    def entry(name,mode,data=b''):
        nonlocal inode
        encoded=name.encode()+b'\0';fields=(inode,mode,0,0,1,0,len(data),0,0,0,0,len(encoded),0)
        output.extend(b'070701'+b''.join(f'{v:08x}'.encode() for v in fields)+encoded)
        output.extend(bytes((-len(output))%4));output.extend(data);output.extend(bytes((-len(output))%4));inode+=1
    entry('httpboot',0o040700);entry('httpboot/embedded-identity',0o040700)
    for name in ('client.key','client.pem','client.csr','ca.pem'):
        path=identity/name
        if path.is_file():entry('httpboot/embedded-identity/'+name,0o100600,path.read_bytes())
    entry('TRAILER!!!',0);output.extend(bytes((-len(output))%512))
    return gzip.compress(bytes(output),mtime=0)


def launch(parts,release,identity,recovery=False):
    with tempfile.TemporaryDirectory(prefix='httpboot-kexec-',dir='/run') as temporary:
        work=Path(temporary);atomic(work/'kernel',parts['.linux'])
        initrd=parts['.initrd']
        atomic(work/'initrd',initrd+bytes((-len(initrd))%4)+identity_overlay(identity))
        command=parts['.cmdline'].rstrip(b'\0').decode('utf-8').strip()
        if 'init=/bin/sh' in command.split():raise ValueError('Unsupported startup repair command line')
        command+=' httpboot.kernel-repair=1 httpboot.release='+release
        if recovery:command+=' httpboot.recovery=1 httpboot.offline-auto=1'
        subprocess.run(['kexec','-l',str(work/'kernel'),'--initrd='+str(work/'initrd'),'--command-line='+command],check=True)
        subprocess.run(['kexec','-e'],check=True)
        raise ValueError('Matching kernel transition unexpectedly returned')


def transition(server,identity,selected,progress):
    if 'httpboot.kernel-repair=1' in Path('/proc/cmdline').read_text().split():
        raise ValueError('Matching-kernel repair already ran once; choose a verified previous image or recovery')
    with tempfile.TemporaryDirectory(prefix='httpboot-kernel-',dir='/run') as temporary:
        work=Path(temporary)
        download(server,selected['release'],'boot.efi',selected['artifacts']['boot.efi'],identity,work/'boot.efi',progress)
        launch(sections(work/'boot.efi'),selected['release'],identity)


def offline_transition(identity,selected,cache=None):
    if 'httpboot.kernel-repair=1' in Path('/proc/cmdline').read_text().split():
        raise ValueError('Matching-kernel repair already ran once; use compatible recovery media')
    candidates=((cache or identity)/'recovery.efi',identity.parents[1]/'EFI/HTTPBOOT/RECOVERY.EFI')
    expected=selected['artifacts']['recovery.efi']['sha256']
    from common import sha256
    image=next((file for file in candidates if file.is_file() and sha256(file)==expected),None)
    if image is None:raise ValueError('Matching verified recovery kernel is not cached; use diagnostics or compatible boot media')
    launch(sections(image),selected['release'],identity,recovery=True)
