"""Unprivileged per-user v2 saver. Network credentials stay in the root service."""
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from client_agent import rpc
from persistence_v2 import Saver,Watcher
from snapshot_store import coherent_folders, needs_clean

STOP=False

def owned_processes():
    for proc in Path('/proc').iterdir():
        try:
            if proc.name.isdigit() and proc.stat().st_uid==os.getuid():yield proc,os.readlink(proc/'exe').removesuffix(' (deleted)')
        except OSError:continue


def closed(rule):
    folder=rule['folder'];lower=folder.lower()
    if folder.startswith('.var/app/'):
        app=folder.split('/')[2]
        result=subprocess.run(['flatpak','ps','--columns=application'],check=True,capture_output=True,text=True)
        return app not in result.stdout.splitlines()
    if lower.startswith('.config/google-chrome'):names=('chrome','google-chrome')
    elif lower.startswith(('.config/chatgpt','.config/codex')):names=('chatgpt','codex')
    elif lower=='.codex' or lower.startswith('.codex/'):names=('codex',)
    else:names=()
    if rule['mode']=='closed-folder':names=(*names,rule['process'].lower())
    target=str(Path.home()/folder).rstrip('/')+'/'
    for proc,path in owned_processes():
        exe=Path(path).name.lower()
        # Standalone/backend Codex accesses .codex, not Electron's UI profile.
        backend=exe=='codex' and '/resources/' in path
        if any(name==exe or rule['mode']=='closed-folder' and name in exe for name in names) and not (backend and lower.startswith('.config/')):return False
        if needs_clean(rule) and int(proc.name)!=os.getpid():
            try:
                for descriptor in (proc/'fd').iterdir():
                    try:opened=os.readlink(descriptor).removesuffix(' (deleted)')
                    except FileNotFoundError:continue
                    if opened.startswith(target):return False
            except (PermissionError,FileNotFoundError):pass
    if lower.startswith('.config/google-chrome'):
        base=Path.home()/folder
        if base.is_dir():
            for profile in base.iterdir():
                if not profile.is_dir() or not (profile.name=='Default' or profile.name.startswith('Profile ')):continue
                try:
                    value=json.loads((profile/'Preferences').read_text()).get('profile',{})
                    if value.get('exit_type')!='Normal' or value.get('exited_cleanly') is False:return False
                except (OSError,ValueError):return False
    return True


def checkpoint(saver,rules,identifiers,call):
    required=coherent_folders(rules)
    if not required:return None
    selected=[r for r in rules if r['folder'] in required]
    if not required<=set(identifiers) or any(not closed(r) or not saver.stable(r) for r in selected):
        raise ValueError('App data or sign-in storage changed; a complete verified save is still pending')
    return call('checkpoint',{'snapshots':{folder:identifiers[folder] for folder in required},'apps_closed':True})['id']


def main():
    action=sys.argv[1]
    state=rpc('state')
    # pam_systemd may start the user service before PAM has restored its data.
    # Do not create/watch/save application folders until restore is complete.
    if action=='daemon':
        while not state.get('session_ready',False):
            time.sleep(0.5);state=rpc('state')
    rules=state['rules']
    def status(**value):rpc('status',value=value)
    saver=Saver(Path.home(),Path('/run/httpboot-v2/users')/str(os.getuid())/'cache.sqlite3',
                lambda route,value:rpc('snapshot',route=route,value=value),status)
    if action=='restore':
        restore_set=rpc('snapshot',route='restore-set',value={})['snapshots'] if state.get('supports_checkpoints') else {}
        for rule in rules:
            saver.restore(rule,restore_set.get(rule['folder']))
            if rule['mode']=='app-only':
                from flatpak_content import restore
                restore(Path.home(),rule['folder'].split('/')[-1])
        return
    if action=='save':
        failures=[];identifiers={}
        for rule in rules:
            try:
                if rule['mode']=='app-only':
                    from flatpak_content import export
                    export(Path.home(),rule['folder'].split('/')[-1],rule['source'],state.get('sources',[]))
                identifiers[rule['folder']]=saver.save(rule,lambda:closed(rule))['id']
            except Exception as error:
                failures.append(rule['folder'])
                status(folder=rule['folder'],phase='pending',message=str(error)[:500],warning='Pending work exists only in RAM')
        if failures:raise ValueError(str(len(failures))+' selected folders are still pending; inspect their status and quit the relevant apps normally')
        identifier=checkpoint(saver,rules,identifiers,lambda route,value:rpc('snapshot',route=route,value=value)) if state.get('supports_checkpoints') else None
        if identifier:status(folder='general',phase='verified',snapshot=identifier,updated=time.time(),message='App data and selected sign-in storage saved together')
        return
    if action!='daemon':raise ValueError('Unknown saver action')
    # Restore only allowlisted appearance settings in the user's D-Bus session.
    try:
        import desktop_state
        desktop_state.restore()
    except (OSError,ValueError,subprocess.SubprocessError):pass
    # Apply appearance settings after restore, in the user's own D-Bus session.
    try:
        from terminal_preferences import apply
        apply()
    except (OSError,ValueError,subprocess.SubprocessError):pass
    subprocess.run(['notify-send','HTTP Boot','Non-persistent apps will not save data'],check=False)
    def stop(*_):
        global STOP
        STOP=True
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    watcher=Watcher([Path.home()/rule['folder'] for rule in rules])
    dirty={r['folder'] for r in rules};last={r['folder']:time.monotonic() for r in rules};retry={};next_appearance=0;identifiers={};last_checkpoint=None;checkpoint_retry=0
    try:
        while not STOP:
            state=rpc('state')
            if state.get('saving_paused'):time.sleep(0.2);continue
            current=state['rules']
            if time.monotonic()>=next_appearance and any(r['folder']=='.local/share/httpboot/desktop-state' for r in current):
                try:
                    import desktop_state
                    desktop_state.capture()
                except (OSError,ValueError,subprocess.SubprocessError):pass
                next_appearance=time.monotonic()+30
            if current!=rules:
                rules=current;watcher.close();watcher=Watcher([Path.home()/rule['folder'] for rule in rules])
                dirty={r['folder'] for r in rules};last={r['folder']:time.monotonic() for r in rules};retry={};identifiers={}
            changed=watcher.changed_roots(0.5)
            for rule in rules:
                if Path.home()/rule['folder'] in changed:dirty.add(rule['folder']);last[rule['folder']]=time.monotonic()
            if dirty:
                for rule in rules:
                    if rule['folder'] not in dirty or time.monotonic()-last[rule['folder']]<2 or time.monotonic()<retry.get(rule['folder'],0):continue
                    try:
                        if rule['mode']=='app-only':
                            from flatpak_content import export
                            export(Path.home(),rule['folder'].split('/')[-1],rule['source'],state.get('sources',[]))
                        identifiers[rule['folder']]=saver.save(rule,lambda:closed(rule))['id'];dirty.discard(rule['folder'])
                    except Exception as error:
                        status(folder=rule['folder'],phase='pending',message=str(error)[:500],warning='Pending work exists only in RAM')
                        retry[rule['folder']]=time.monotonic()+15
            required=coherent_folders(rules)
            signature=tuple(sorted((folder,identifiers.get(folder)) for folder in required))
            if state.get('supports_checkpoints') and required and not required&dirty and required<=set(identifiers) and signature!=last_checkpoint and time.monotonic()>=checkpoint_retry:
                try:
                    identifier=checkpoint(saver,rules,identifiers,lambda route,value:rpc('snapshot',route=route,value=value)) if state.get('supports_checkpoints') else None
                    last_checkpoint=signature
                    status(folder='general',phase='verified',snapshot=identifier,updated=time.time(),message='App data and selected sign-in storage saved together')
                except Exception:
                    checkpoint_retry=time.monotonic()+15
                    status(folder='general',phase='pending',message='Waiting for a coherent app-data and sign-in save; previous complete saves are retained')
    finally:watcher.close()

if __name__=='__main__':
    try:main()
    except Exception as error:
        import traceback
        frames=traceback.extract_tb(error.__traceback__)
        frame=next((f for f in reversed(frames) if Path(f.filename).parent==Path(__file__).parent),None)
        code=type(error).__name__+(':'+Path(frame.filename).name+':'+str(frame.lineno) if frame else '')
        print('HTTPBOOT_WORKER_ERROR='+code,file=sys.stderr)
        sys.exit(1)
