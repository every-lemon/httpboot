"""Approve inspected firmware/driver packages without building arbitrary source."""
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from common import atomic,dump,load,sha256


def inspect(path,kernel,hardware_ids,provenance,architecture='amd64'):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size>512*1024**2:
        raise ValueError('Import must be a regular file up to 512 MiB')
    if architecture!='amd64':raise ValueError('Only amd64 driver packages are supported')
    if not re.fullmatch(r'[A-Za-z0-9._+-]{1,128}',kernel):raise ValueError('Invalid kernel version')
    if not isinstance(hardware_ids,list) or not hardware_ids or any(not isinstance(v,str) or len(v)>256 for v in hardware_ids):
        raise ValueError('Record the matching hardware IDs')
    if not isinstance(provenance,str) or not 1<=len(provenance)<=1024:raise ValueError('Record import provenance')
    result={'schema':1,'sha256':sha256(path),'size':path.stat().st_size,'kernel':kernel,
            'architecture':architecture,'hardware_ids':hardware_ids,'provenance':provenance,'filename':path.name}
    if path.suffix=='.deb':
        fields=subprocess.run(['dpkg-deb','--field',str(path),'Package','Architecture'],check=True,capture_output=True,text=True).stdout
        if not re.search(r'Architecture: (amd64|all)\s*$',fields,re.M):raise ValueError('Package architecture is incompatible')
        contents=subprocess.run(['dpkg-deb','--contents',str(path)],check=True,capture_output=True,text=True).stdout
        control=subprocess.run(['dpkg-deb','--ctrl-tarfile',str(path)],check=True,capture_output=True).stdout
        import io,tarfile
        with tarfile.open(fileobj=io.BytesIO(control)) as archive:
            names={Path(m.name).name for m in archive.getmembers()}
            if names & {'preinst','postinst','prerm','postrm','triggers'}:
                raise ValueError('Driver package scripts require a separately reviewed image recipe')
        process=subprocess.Popen(['dpkg-deb','--fsys-tarfile',str(path)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        total=0;count=0
        try:
            with tarfile.open(fileobj=process.stdout,mode='r|') as archive:
                for member in archive:
                    name=member.name.removeprefix('./');count+=1
                    if count>50000:raise ValueError('Too many files in driver package')
                    if not name or name=='.':continue
                    if name.startswith('/') or '..' in Path(name).parts or not (member.isdir() or member.isfile()):
                        raise ValueError('Driver package contains an unsafe path, link or special file')
                    if member.isfile() and not name.startswith(('usr/lib/firmware/','lib/firmware/','usr/lib/modules/','lib/modules/','usr/share/doc/')):
                        raise ValueError('Driver package contains files outside firmware, modules and documentation')
                    if member.uid!=0 or member.gid!=0 or member.mode&0o022:raise ValueError('Driver files and directories must be root-owned and not writable by other accounts')
                    if member.mode & 0o7000:raise ValueError('Privileged file modes are not permitted in driver packages')
                    if member.isfile() and re.search(r'\.ko(?:\.(?:xz|zst|gz))?$',name):
                        if member.size>128*1024**2:raise ValueError('Compiled module is too large')
                        with tempfile.TemporaryDirectory() as temporary:
                            module=Path(temporary)/Path(name).name
                            module.write_bytes(archive.extractfile(member).read())
                            vermagic=subprocess.run(['modinfo','-F','vermagic',str(module)],capture_output=True,text=True,check=True).stdout.split()
                            if not vermagic or vermagic[0]!=kernel:raise ValueError('Compiled module vermagic differs from the selected kernel')
                    total+=member.size
                    if total>2*1024**3:raise ValueError('Unpacked driver package is too large')
            if process.wait(timeout=30):raise ValueError('Unable to inspect driver package contents')
        finally:
            if process.poll() is None:process.kill();process.wait()
            process.stdout.close()
        if re.search(r'(?:dkms|/usr/src/)',contents,re.I):raise ValueError('DKMS/source builds are outside this importer')
        modules=re.findall(r'\S+\.ko(?:\.(?:xz|zst|gz))?',contents)
        if modules and any('/'+kernel+'/' not in name for name in modules):raise ValueError('Compiled modules do not match the selected kernel')
        result.update(kind='package',modules=bool(modules),module_names=[Path(name).name.split('.ko')[0].replace('-','_') for name in modules])
    elif path.suffix in ('.bin','.fw','.ucode'):
        result.update(kind='firmware',modules=False)
    else:raise ValueError('Select a firmware file or compatible binary .deb')
    return result


def approve(folder,path,record):
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=True,mode=0o700)
    if sha256(path)!=record['sha256']:raise ValueError('Import changed after inspection')
    target=folder/record['sha256'];target.mkdir(mode=0o700,exist_ok=True)
    atomic(target/'payload',Path(path).read_bytes())
    dump(target/'record.json',{**record,'approved':True,'result':'retained-for-image-build'})
    return target


def apply(folder,root,kernel):
    """Caller operates on a staging image; errors cannot replace a deployed image."""
    imported=[]
    for record_file in Path(folder).glob('*/record.json'):
        record=load(record_file);payload=record_file.parent/'payload'
        if record.get('approved') is not True or sha256(payload)!=record['sha256']:raise ValueError('Approved driver integrity failed')
        if record['modules'] and record['kernel']!=kernel:raise ValueError('Approved compiled module requires its original kernel; retain previous image')
        if record['kind']=='firmware':
            name=record['filename']
            if Path(name).name!=name or not re.fullmatch(r'[A-Za-z0-9_.+-]+',name):raise ValueError('Invalid firmware name')
            atomic(Path(root)/'usr/lib/firmware'/name,payload.read_bytes(),0o644)
        else:
            # No package scripts were accepted. Extract binary contents only into staging.
            subprocess.run(['dpkg-deb','--extract',str(payload),str(root)],check=True)
            imported.extend(record.get('module_names',[]))
    subprocess.run(['chroot',str(root),'depmod','-a',kernel],check=True)
    return imported
