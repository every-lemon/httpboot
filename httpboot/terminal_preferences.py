"""One-time terminal cell/font repair with persisted user preferences."""
import ast,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
FONT_SHA='c805f9436dbc268644c1d9584f01a601a653e028e08fd74b9b949f6cf8304d88'
HOME=Path.home()
BASE=HOME/'.local/share/httpboot/desktop-state'
PROFILE_KEYS=('font','use-system-font','cell-width-scale','cell-height-scale','default-size-columns','default-size-rows')

def call(*args):return subprocess.run(['gsettings',*args],check=True,capture_output=True,text=True,timeout=10).stdout.strip()
def profile_schema(identifier):
    if not isinstance(identifier,str) or not re.fullmatch('[a-f0-9-]{36}',identifier):raise ValueError('Invalid terminal profile identity')
    return 'org.gnome.Terminal.Legacy.Profile:/org/gnome/terminal/legacy/profiles:/:'+identifier+'/'
def profiles():
    if 'org.gnome.Terminal.ProfilesList' not in call('list-schemas').splitlines():return []
    text=call('get','org.gnome.Terminal.ProfilesList','list')
    values=ast.literal_eval(text.removeprefix('@as '))
    default=ast.literal_eval(call('get','org.gnome.Terminal.ProfilesList','default'))
    result=list(dict.fromkeys([*values,default]))
    for value in result:profile_schema(value)
    return result

def install(font=None):
    if os.geteuid()!=0:raise ValueError('Installing the shared font requires root')
    font=font or Path(__file__).with_name('DejaVuSansMono.ttf')
    if hashlib.sha256(font.read_bytes()).hexdigest()!=FONT_SHA:raise ValueError('Terminal font checksum mismatch')
    target=Path('/usr/local/share/fonts/httpboot');target.parent.mkdir(parents=True,exist_ok=True);target.parent.chmod(0o755);target.mkdir(parents=True,exist_ok=True);target.chmod(0o755)
    shutil.copyfile(font,target/font.name);os.chmod(target/font.name,0o644)
    license=font.with_name('DejaVuSansMono-LICENSE.txt')
    if license.exists():shutil.copyfile(license,target/license.name)
    subprocess.run(['fc-cache','-f',str(target)],check=True,capture_output=True,timeout=30)

def capture():
    return {identifier:{key:call('get',profile_schema(identifier),key) for key in PROFILE_KEYS} for identifier in profiles()}
def restore(values):
    if not isinstance(values,dict):raise ValueError('Invalid terminal settings')
    for identifier,fields in values.items():
        schema=profile_schema(identifier)
        if not isinstance(fields,dict) or set(fields)-set(PROFILE_KEYS):raise ValueError('Unexpected terminal setting')
        for key,value in fields.items():
            if not isinstance(value,str) or len(value)>300:raise ValueError('Invalid terminal setting value')
            call('set',schema,key,value)

def apply(force=False):
    marker=BASE/'terminal-font-v2.json'
    if marker.exists() and not force:return False
    call('set','org.gnome.desktop.interface','monospace-font-name',"'DejaVu Sans Mono 11'")
    defaults={'font':"'DejaVu Sans Mono 11'",'use-system-font':'false','cell-width-scale':'1.0','cell-height-scale':'1.0','default-size-columns':'100','default-size-rows':'28'}
    for identifier in profiles():
        for key,value in defaults.items():call('set',profile_schema(identifier),key,value)
    BASE.mkdir(parents=True,exist_ok=True,mode=0o700)
    marker.write_text(json.dumps({'schema':1,'font':'DejaVu Sans Mono 11'}));marker.chmod(0o600)
    return True
if __name__=='__main__':apply(force='--force' in __import__('sys').argv)
