"""Read-only Sober evidence collection; private logs are classified, never exported."""
import json
import os
import subprocess
from pathlib import Path

PATTERNS={'out_of_memory':('outofmemory','failed to allocate memory'),
          'graphics_initialization':('vkgetphysicaldevice','no supported graphics','vulkan'),
          'download_failure':('download failed','manifest could not','failed to download'),
          'lingering_instance':('frozen instance','already running'),
          'permission_failure':('permission denied','operation not permitted')}


def collect(home=None):
    home=Path(home or Path.home());base=home/'.var/app/org.vinegarhq.Sober'
    memory={line.split(':')[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith(('MemAvailable:','MemTotal:'))}
    fs=os.statvfs(home)
    result={'schema':1,'memory':memory,'available_storage_bytes':fs.f_bavail*fs.f_frsize,
            'sse42':'sse4_2' in Path('/proc/cpuinfo').read_text(),'log_categories':[],
            'profile_present':base.is_dir(),'profile_owned_by_user':not base.exists() or base.stat().st_uid==os.getuid()}
    for args,key in ((['flatpak','info','--user','--show-permissions','org.vinegarhq.Sober'],'permissions'),
                     (['flatpak','ps','--columns=application'],'processes'),(['vulkaninfo','--summary'],'graphics')):
        try:
            proc=subprocess.run(args,capture_output=True,text=True,timeout=20)
            result[key+'_exit']=proc.returncode
            if key=='processes':result['running']='org.vinegarhq.Sober' in proc.stdout.splitlines()
            if key=='permissions':result['graphics_device_permission']='dri' in proc.stdout or 'devices=all' in proc.stdout
        except (OSError,subprocess.TimeoutExpired):result[key+'_exit']=None
    logs=base/'data/sober/sober_logs'
    categories=set()
    for file in sorted(logs.glob('*'),key=lambda p:p.stat().st_mtime,reverse=True)[:3]:
        if file.is_symlink() or not file.is_file():continue
        with open(file,'rb') as stream:text=stream.read(512*1024).decode(errors='replace').lower()
        for category,patterns in PATTERNS.items():
            if any(pattern in text for pattern in patterns):categories.add(category)
    result['log_categories']=sorted(categories)
    result['finding']='profile-ownership-integration-fault' if not result['profile_owned_by_user'] else 'no-demonstrated-httpboot-fault'
    return result

if __name__=='__main__':print(json.dumps(collect(),indent=2))
