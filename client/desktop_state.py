#!/usr/bin/env python3
"""Allowlisted per-user appearance state, independent of the volatile Downloads folder."""
import ast,hashlib,json,os,shutil,subprocess
from pathlib import Path
HOME=Path.home()
BASE=HOME/'.local/share/httpboot/desktop-state'
KEYS={'org.gnome.desktop.background':('picture-uri','picture-uri-dark','picture-options','primary-color','secondary-color'),
      'org.gnome.desktop.interface':('color-scheme','gtk-theme','icon-theme','monospace-font-name'),
      'org.gnome.shell':('favorite-apps',),
      'org.gnome.shell.extensions.dash-to-dock':('dock-position','dash-max-icon-size','extend-height','dock-fixed','intellihide','autohide','transparency-mode','background-opacity')}
ALIASES={'httpboot-roblox.desktop':'org.vinegarhq.Sober.desktop','httpboot-prism.desktop':'org.prismlauncher.PrismLauncher.desktop'}
def call(*args):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=10).stdout.strip()
def capture():
    from urllib.parse import urlparse,unquote
    BASE.mkdir(parents=True,exist_ok=True,mode=0o700);values={}
    schemas=set(call('gsettings','list-schemas').splitlines())
    for schema,keys in KEYS.items():
        if schema not in schemas:continue
        for key in keys:
            value=call('gsettings','get',schema,key)
            if schema=='org.gnome.desktop.background' and key.startswith('picture-uri'):
                uri=ast.literal_eval(value);parsed=urlparse(uri)
                if parsed.scheme=='file':
                    source=Path(unquote(parsed.path))
                    if source.is_file():
                        digest=hashlib.sha256(source.read_bytes()).hexdigest();target=BASE/'wallpapers'/digest
                        target.parent.mkdir(exist_ok=True,mode=0o700)
                        if not target.exists():shutil.copyfile(source,target);target.chmod(0o600)
                        value=repr(target.as_uri())
            if key=='favorite-apps':value=repr(list(dict.fromkeys(ALIASES.get(x,x) for x in ast.literal_eval(value))))
            values[schema+'/'+key]=value
    import terminal_preferences
    data=json.dumps({'schema':1,'values':values,'terminal_profiles':terminal_preferences.capture()},sort_keys=True)
    path=BASE/'settings.json';old=path.read_text() if path.exists() else ''
    if data!=old:
        temp=BASE/'settings.tmp';temp.write_text(data);temp.chmod(0o600);os.replace(temp,path)
    return data!=old

def restore():
    path=BASE/'settings.json'
    if not path.exists():return
    data=json.loads(path.read_text())
    if data.get('schema')!=1:raise ValueError('Unsupported desktop settings snapshot')
    import terminal_preferences
    terminal_preferences.restore(data.get('terminal_profiles',{}))
    for name,value in data['values'].items():
        schema,key=name.rsplit('/',1)
        if key not in KEYS.get(schema,()):raise ValueError('Unexpected desktop setting')
        if key=='favorite-apps':value=repr(list(dict.fromkeys(ALIASES.get(x,x) for x in ast.literal_eval(value))))
        call('gsettings','set',schema,key,value)
if __name__=='__main__':
    import sys
    if sys.argv[1:] == ['restore']:restore()
    else:capture()
