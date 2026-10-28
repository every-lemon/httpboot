"""Scheduled Server maintenance and qualified image preparation on a combined Builder."""
import argparse
import fcntl
import json
import time
from pathlib import Path
from types import SimpleNamespace
from common import dump,load
from schedule_policy import claim,finish,defaults,due
from product_version import VERSION


def tick(authority):
    lock_path=authority.database.parent/'maintenance.lock'
    with open(lock_path,'a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return {'state':'deferred','reason':'Another maintenance operation is active'}
        with authority.db() as db:
            # The exclusive executor lock proves that any persisted active marker
            # belongs to an interrupted run. Keep its daily claim to avoid repeats.
            db.execute("DELETE FROM settings WHERE key='maintenance-active'")
            row=db.execute("SELECT value FROM settings WHERE key='schedules'").fetchone()
            policy=json.loads(row[0]) if row else defaults()
            builder=db.execute("SELECT value FROM settings WHERE key='local-builder'").fetchone()
            builder=json.loads(builder[0]) if builder else None
            remote=db.execute("SELECT value FROM settings WHERE key='remote-builder'").fetchone()
            remote=json.loads(remote[0]) if remote else None
            legacy=db.execute("SELECT value FROM settings WHERE key='legacy-import'").fetchone()
            sessions=db.execute('SELECT COUNT(*) FROM sessions').fetchone()[0]
            transfers=db.execute("SELECT COUNT(*) FROM image_pins WHERE reason LIKE 'transfer:%'").fetchone()[0]
        result=[];now=time.time()
        pending=authority.database.parent/'remote-build.json'
        remote_active=pending.exists() and load(pending).get('state') not in ('published','failed')
        if due(policy,'host_packages',0,now):
            if remote_active or sessions or transfers or (legacy and json.loads(legacy[0]).get('legacy_service_required')):
                result.append({'kind':'host_packages','state':'deferred','reason':'Client sessions, downloads, image preparation or legacy transition remain active'})
            else:
                token=claim(authority,'host_packages',now)
                if token:
                    try:
                        from maintenance import packages
                        reboot=packages(authority.database.parent/'maintenance-logs'/str(time.time_ns()))
                        result.append({'kind':'host_packages','state':'completed','host_reboot_required':reboot})
                    finally:finish(authority,token)
        if remote:
            from server_jobs import tick as remote_tick
            result.append(remote_tick(authority,remote,now))
        elif due(policy,'image_updates',0,now):
            if not builder:result.append({'kind':'image_updates','state':'deferred','reason':'Configure a healthy matching Builder'})
            else:
                from build_public import require_builder,build
                require_builder()
                token=claim(authority,'image_updates',now,{'state':'healthy','version':VERSION,'seen':now})
                if token:
                    try:
                        release='auto-'+time.strftime('%Y%m%d-%H%M%S')
                        output=Path(builder['output'])/release
                        args=SimpleNamespace(server=builder['server'],ca=Path(builder['ca']),output=output,
                            cache=Path(builder['cache']),jobs=builder.get('jobs',2),drivers=Path(builder['drivers']) if builder.get('drivers') else (authority.database.parent/'approved-drivers' if (authority.database.parent/'approved-drivers').exists() else None),
                            private_base=Path(builder['private_base']) if builder.get('private_base') else None,
                            legacy_config=Path(builder['legacy_config']) if builder.get('legacy_config') else None,
                            refresh_packages=True,validate_startup=True)
                        build(args)
                        authority.images.publish(release,output,output/'qualification-v2.json')
                        result.append({'kind':'image_updates','state':'published','release':release})
                    finally:finish(authority,token)
        from release_cleanup import cleanup,tools
        cleanup(authority,now,apply=True)
        tools(Path('/opt/httpboot'),Path('/var/lib/httpboot'),Path('/var/lib/httpboot-build-cache'),now,apply=True)
        value={'state':'checked','operations':result,'time':now}
        dump(authority.database.parent/'maintenance-status.json',value)
        return value
