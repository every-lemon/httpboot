"""Arrow-key import of administrator-mounted USB driver files."""
import argparse
import json
import os
import subprocess
from pathlib import Path
from driver_imports import inspect,approve


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--media',type=Path,required=True)
    parser.add_argument('--server-config',type=Path,help='Submit to this configured Server for approval')
    parser.add_argument('--store',type=Path,required=True)
    parser.add_argument('--kernel',default=os.uname().release)
    args=parser.parse_args()
    if os.geteuid()!=0:parser.error('Driver imports require administrator authentication')
    media=args.media.resolve(strict=True)
    result=subprocess.run(['findmnt','-n','-o','TARGET','--target',str(media)],check=True,capture_output=True,text=True).stdout.strip()
    if result=='/':raise ValueError('Select an explicitly mounted USB filesystem')
    files=[p for p in media.rglob('*') if p.is_file() and not p.is_symlink() and p.suffix in ('.deb','.bin','.fw','.ucode')]
    if len(files)>500:raise ValueError('Too many import candidates; select a smaller USB folder')
    choices=[]
    for number,file in enumerate(files):choices.extend([str(number),str(file.relative_to(media))])
    if not choices:raise ValueError('No compatible firmware or binary driver packages found')
    selected=subprocess.run(['whiptail','--title','HTTP Boot USB driver import','--menu',
                             'Select a driver file. Source and DKMS builds are unsupported.','22','80','12',*choices],
                            stderr=subprocess.PIPE,text=True)
    if selected.returncode:return
    file=files[int(selected.stderr.strip())]
    ids=[]
    for path in Path('/sys/devices').glob('**/modalias'):
        try:
            value=path.read_text().strip()
            if value:ids.append(value)
        except OSError:continue
        if len(ids)>=128:break
    record=inspect(file,args.kernel,ids,'Administrator-selected USB media')
    answer=subprocess.run(['whiptail','--title','Approve driver import','--yesno',json.dumps(record,indent=2),'24','90'])
    if answer.returncode:return
    if args.server_config:
        from common import load
        from driver_store import submit
        config=load(args.server_config)
        print(json.dumps(submit(config['server'],config['identity'],file,record)))
        return
    target=approve(args.store,file,record)
    print('Approved import retained at '+str(target))

if __name__=='__main__':main()
